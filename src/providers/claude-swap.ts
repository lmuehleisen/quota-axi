import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { findCommandPath } from "../lib/process.js";

/**
 * Opt-in: report one Claude lane per account claude-swap manages, read from
 * the JSON its own `cswap list --json` prints. quota-axi receives usage and
 * account labels only; claude-swap keeps every credential it manages.
 */
const CLAUDE_SWAP_ENV = "QUOTA_AXI_CLAUDE_SWAP";
export const CLAUDE_SWAP_SOURCE = "claude-swap";

const COMMAND = "cswap";
const ARGS = ["list", "--json"] as const;
/** claude-swap 0.26 bounds each usage fetch at 5s and a token refresh at 10s. */
const WAIT_MS = 30_000;
const OUTPUT_LIMIT_BYTES = 1_048_576;
export const CLAUDE_SWAP_EXECUTABLE_REMEDY = "pipx install claude-swap";
// This detached collector keeps draining cswap after a timeout while storing
// no more than the output limit, so the refresh-capable child is not blocked.
const OUTPUT_RUNNER = String.raw`
import { spawn } from "node:child_process";
import { closeSync, openSync, rmSync, writeSync } from "node:fs";
import { join } from "node:path";

const [executable, outputDirectory, argsJson, limitText] = process.argv.slice(-4);
const outputPath = join(outputDirectory, "stdout");
const limit = Number(limitText);
let outputFd;
let written = 0;
let overflow = false;
let captureFailed = false;
let disconnected = false;
let finished = false;
let child;

function closeOutput() {
  if (outputFd === undefined) return;
  try {
    closeSync(outputFd);
  } catch {
    // Closing a temporary output file is best effort.
  }
  outputFd = undefined;
}

function cleanup() {
  closeOutput();
  try {
    rmSync(outputDirectory, { recursive: true, force: true });
  } catch {
    // Temporary output cleanup is best effort.
  }
}

function report(result) {
  finished = true;
  closeOutput();
  if (disconnected) {
    cleanup();
    return;
  }
  process.stdout.write(JSON.stringify(result) + "\n", (error) => {
    if (error || disconnected) cleanup();
  });
}

process.stdin.on("data", (data) => {
  if (data.toString().includes("ack")) disconnected = true;
});
process.stdin.on("end", () => {
  disconnected = true;
  if (finished) cleanup();
});
process.stdin.resume();
process.stdout.on("error", () => {
  disconnected = true;
  if (finished) cleanup();
});

try {
  outputFd = openSync(outputPath, "wx", 0o600);
} catch {
  report({ error: true });
}

if (outputFd !== undefined) {
  try {
    child = spawn(executable, JSON.parse(argsJson), {
      stdio: ["ignore", "pipe", "ignore"],
      detached: true,
      windowsHide: true,
      env: process.env,
    });
  } catch {
    report({ error: true });
  }
  if (child) {
    child.stdout.on("data", (chunk) => {
      if (overflow || captureFailed) return;
      const remaining = limit - written;
      const allowed = Math.min(remaining, chunk.length);
      try {
        let offset = 0;
        while (offset < allowed) {
          const count = writeSync(outputFd, chunk, offset, allowed - offset);
          if (count <= 0) throw new Error("output_write_failed");
          offset += count;
        }
        written += allowed;
        if (allowed < chunk.length) overflow = true;
      } catch {
        captureFailed = true;
      }
    });
    child.on("error", () => {
      captureFailed = true;
    });
    child.on("close", (code) => {
      report({ code, overflow, captureFailed });
    });
  }
}
`;
const CHILD_ENVIRONMENT_KEYS = new Set([
  "HOME",
  "PATH",
  "USER",
  "LOGNAME",
  "SHELL",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "TERM",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
]);
const WINDOWS_CHILD_ENVIRONMENT_KEYS = new Set([
  "SYSTEMROOT",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "PATHEXT",
  "COMSPEC",
]);

type ClaudeSwapWindow = {
  pct: number;
  resetsAt?: string;
};

type ClaudeSwapUsage = {
  fiveHour?: ClaudeSwapWindow;
  sevenDay?: ClaudeSwapWindow;
};

export type ClaudeSwapAccount = {
  accountKey: string;
  email: string;
  organization?: string;
  /** claude-swap's own `usageStatus`; only `ok` carries `usage`. */
  usageStatus: string;
  /** The `usage` object as printed. */
  usage?: ClaudeSwapUsage;
  /** When claude-swap measured `usage`. */
  fetchedAt?: string;
};

export function claudeSwapEnabled(env = process.env): boolean {
  const value = env[CLAUDE_SWAP_ENV]?.trim().toLowerCase();
  return value === "1" || value === "true";
}

/**
 * The accounts `cswap list --json` (schema 1) reports, in its order. Throws
 * when the command is missing, fails, or prints anything but schema 1 with
 * valid, uniquely keyed account rows.
 */
export async function readClaudeSwapAccounts(): Promise<ClaudeSwapAccount[]> {
  const payload = objectValue(JSON.parse(await runCswapList()));
  if (payload?.schemaVersion !== 1 || !Array.isArray(payload.accounts))
    throw new Error("claude_swap_malformed");
  const keys = new Set<string>();
  const accounts = payload.accounts.map((raw): ClaudeSwapAccount => {
    const row = objectValue(raw);
    if (!row) throw new Error("claude_swap_malformed");
    const email = requiredString(row.email);
    const organizationUuid = stringIncludingEmpty(row.organizationUuid);
    const organization = optionalString(row, "organizationName");
    const usageStatus = requiredString(row.usageStatus);
    if (!Object.hasOwn(row, "usage")) throw new Error("claude_swap_malformed");
    const usage = parseUsage(row.usage);
    const fetchedAt = optionalDate(row, "usageFetchedAt");
    if (usage && !fetchedAt) throw new Error("claude_swap_malformed");
    const accountKey = `claude-swap:${createHash("sha256")
      .update(JSON.stringify([email, organizationUuid]))
      .digest("hex")
      .slice(0, 24)}`;
    if (keys.has(accountKey)) throw new Error("claude_swap_malformed");
    keys.add(accountKey);
    return {
      accountKey,
      email,
      ...(organization !== undefined ? { organization } : {}),
      usageStatus,
      ...(usage ? { usage } : {}),
      ...(fetchedAt ? { fetchedAt } : {}),
    };
  });
  if (accounts.length === 0) throw new Error("claude_swap_malformed");
  return accounts;
}

/**
 * `cswap list --json` may renew a credential claude-swap manages while it
 * fetches usage, so a slow run is waited out and then left running, never
 * signalled: killing it mid-exchange could leave its store holding a spent
 * refresh token. It gets no stdin and its own process group, like a delegate.
 */
async function runCswapList(): Promise<string> {
  const executable = await findCommandPath(COMMAND);
  if (
    !executable ||
    [".cmd", ".bat"].includes(win32.extname(executable).toLowerCase())
  )
    throw new Error("claude_swap_unavailable", {
      cause: CLAUDE_SWAP_EXECUTABLE_REMEDY,
    });
  const childEnvironment = claudeSwapEnvironment();
  let outputDirectory: string;
  try {
    outputDirectory = await mkdtemp(join(tmpdir(), "quota-axi-cswap-"));
  } catch {
    throw new Error("claude_swap_unavailable");
  }
  const outputPath = join(outputDirectory, "stdout");
  let child: ChildProcess;
  try {
    child = spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        OUTPUT_RUNNER,
        executable,
        outputDirectory,
        JSON.stringify(ARGS),
        String(OUTPUT_LIMIT_BYTES),
      ],
      {
        stdio: ["pipe", "pipe", "ignore"],
        detached: true,
        windowsHide: true,
        env: childEnvironment,
      },
    );
  } catch {
    await removeOutput(outputDirectory);
    throw new Error("claude_swap_spawn_failed");
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const walkAway = (error: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.unref();
      child.stdin?.end();
      child.stdout?.on("error", () => undefined);
      child.stdout?.destroy();
      reject(new Error(error));
    };
    const timer = setTimeout(() => walkAway("claude_swap_timed_out"), WAIT_MS);
    child.on("error", () => {
      if (settled) {
        return;
      }
      void finish({ error: true });
    });
    child.stdout?.setEncoding("utf8");
    let statusLine = "";
    child.stdout?.on("data", (chunk: string) => {
      statusLine += chunk;
      const newline = statusLine.indexOf("\n");
      if (newline < 0) {
        if (statusLine.length > 1_024) void finish({ error: true });
        return;
      }
      try {
        void finish(JSON.parse(statusLine.slice(0, newline)) as RunnerResult);
      } catch {
        void finish({ error: true });
      }
    });
    child.on("close", () => {
      if (settled) return;
      void finish({ error: true });
    });

    async function finish(result: RunnerResult): Promise<void> {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        if (result.error || result.captureFailed)
          throw new Error("claude_swap_spawn_failed");
        if (result.code !== 0) throw new Error("claude_swap_exit_status");
        if (result.overflow) throw new Error("claude_swap_output_too_large");
        const output = await readFile(outputPath, "utf8");
        child.stdin?.end("ack");
        await removeOutput(outputDirectory);
        resolve(output);
      } catch (error) {
        child.stdin?.end("ack");
        await removeOutput(outputDirectory);
        reject(
          error instanceof Error
            ? error
            : new Error("claude_swap_spawn_failed"),
        );
      }
    }
  });
}

function claudeSwapEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  const windows = process.platform === "win32";
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    const comparedKey = windows ? key.toUpperCase() : key;
    if (
      CHILD_ENVIRONMENT_KEYS.has(comparedKey) ||
      comparedKey.startsWith("LC_") ||
      (windows && WINDOWS_CHILD_ENVIRONMENT_KEYS.has(comparedKey))
    ) {
      environment[key] = value;
    }
  }
  return environment;
}

async function removeOutput(outputDirectory: string): Promise<void> {
  await rm(outputDirectory, { recursive: true, force: true }).catch(
    () => undefined,
  );
}

type RunnerResult = {
  code?: number | null;
  overflow?: boolean;
  captureFailed?: boolean;
  error?: boolean;
};

function parseUsage(value: unknown): ClaudeSwapUsage | undefined {
  if (value === null) return undefined;
  const usage = objectValue(value);
  if (!usage) throw new Error("claude_swap_malformed");
  const fiveHour = optionalWindow(usage, "fiveHour");
  const sevenDay = optionalWindow(usage, "sevenDay");
  return {
    ...(fiveHour ? { fiveHour } : {}),
    ...(sevenDay ? { sevenDay } : {}),
  };
}

function optionalWindow(
  usage: Record<string, unknown>,
  key: string,
): ClaudeSwapWindow | undefined {
  if (!Object.hasOwn(usage, key)) return undefined;
  const value = objectValue(usage[key]);
  const resetsAt = value?.resetsAt ?? undefined;
  if (
    !value ||
    !Number.isFinite(value.pct) ||
    (resetsAt !== undefined && !validDate(resetsAt))
  )
    throw new Error("claude_swap_malformed");
  // An idle window has no reset; a native read keeps it the same way
  return { pct: value.pct as number, resetsAt: resetsAt as string | undefined };
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "")
    throw new Error("claude_swap_malformed");
  return value;
}

function stringIncludingEmpty(value: unknown): string {
  if (typeof value !== "string") throw new Error("claude_swap_malformed");
  return value;
}

function optionalString(
  row: Record<string, unknown>,
  key: string,
): string | undefined {
  if (!Object.hasOwn(row, key)) return undefined;
  return stringIncludingEmpty(row[key]);
}

function optionalDate(
  row: Record<string, unknown>,
  key: string,
): string | undefined {
  if (!Object.hasOwn(row, key)) return undefined;
  const value = row[key];
  if (!validDate(value)) throw new Error("claude_swap_malformed");
  return value;
}

function validDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value !== "" &&
    Number.isFinite(Date.parse(value))
  );
}
