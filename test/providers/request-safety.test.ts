import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  quotaJsonReport,
  redactedResponse,
  renderQuotaToon,
} from "../../src/render.js";
import { renderQuotaTui } from "../../src/tui.js";
import { withQuotaSemantics } from "../../src/interpretation.js";
import type { ProviderQuota, QuotaAxiResponse } from "../../src/types.js";
import { PROVIDER_RESPONSE_LIMIT_BYTES } from "../../src/lib/http.js";

const token = "SYNTHETIC_ACCESS_CANARY";
const email = "canary@example.com";
const account = "SYNTHETIC_ACCOUNT_CANARY";
const secretText = `${token} ${email} ${account}`;
let directory: string;
const sources = [
  "claude-file",
  "claude-env",
  "claude-keychain",
  "claude-profile-only",
  "codex-native",
  "codex-pi",
  "cursor",
] as const;
type Source = (typeof sources)[number];
const options = { allowKeychainPrompt: false, refreshCredentials: false };

beforeEach(() => {
  vi.resetModules();
  directory = mkdtempSync(join(tmpdir(), "quota-request-safety-"));
  vi.spyOn(process, "platform", "get").mockReturnValue("linux");
  for (const [name, value] of Object.entries({
    CLAUDE_CONFIG_DIR: directory,
    CODEX_HOME: directory,
    PI_CODING_AGENT_DIR: join(directory, "pi"),
    CURSOR_STATE_DB: join(directory, "state.vscdb"),
    CURSOR_CLI_CONFIG: join(directory, "cursor.json"),
    XDG_CACHE_HOME: join(directory, "cache"),
    XDG_CONFIG_HOME: join(directory, "config"),
    USER: "fixture-user",
    CLAUDE_CODE_OAUTH_TOKEN: "",
    QUOTA_AXI_CODEX_BINARY: "",
  }))
    vi.stubEnv(name, value);
  vi.doMock("../../src/lib/process.js", () => ({
    findCommandPath: vi.fn(async () => undefined),
    commandExists: vi.fn(async () => true),
    terminateChild: vi.fn(),
    execFileText: vi.fn(async (command: string, args: string[]) => {
      if (command === "security")
        return args.includes("-w")
          ? JSON.stringify({ claudeAiOauth: { accessToken: token } })
          : "";
      if (command === "sqlite3")
        return args.join(" ").includes("accessToken")
          ? JSON.stringify(token)
          : "";
      throw new Error("unexpected synthetic process call");
    }),
  }));
  vi.doMock("../../src/lib/running-processes.js", () => ({
    listRunningCommandLines: vi.fn(async () => []),
  }));
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.doUnmock("../../src/lib/process.js");
  vi.doUnmock("../../src/lib/running-processes.js");
  rmSync(directory, { recursive: true, force: true });
});
async function fetchSource(source: Source): Promise<ProviderQuota> {
  if (source.startsWith("claude")) {
    if (source === "claude-env") vi.stubEnv("CLAUDE_CODE_OAUTH_TOKEN", token);
    else if (source === "claude-keychain")
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin");
    else
      writeFileSync(
        join(directory, ".credentials.json"),
        JSON.stringify({ claudeAiOauth: { accessToken: token } }),
      );
    const { claudeAdapter } = await import("../../src/providers/claude.js");
    return claudeAdapter.fetchQuota({
      ...options,
      allowKeychainPrompt: source === "claude-keychain",
      ...(source === "claude-profile-only"
        ? { credentialMode: "profile-only" as const }
        : {}),
    });
  }
  if (source.startsWith("codex")) {
    if (source === "codex-pi") {
      mkdirSync(join(directory, "pi"));
      writeFileSync(
        join(directory, "pi", "auth.json"),
        JSON.stringify({
          "openai-codex": {
            type: "oauth",
            access: token,
            expires: Date.now() + 3_600_000,
            accountId: account,
          },
        }),
      );
    } else
      writeFileSync(
        join(directory, "auth.json"),
        JSON.stringify({
          tokens: { access_token: token, account_id: account },
        }),
      );
    const { createCodexAdapter } = await import("../../src/providers/codex.js");
    return createCodexAdapter().fetchQuota(options);
  }
  const { cursorAdapter } = await import("../../src/providers/cursor.js");
  return cursorAdapter.fetchQuota(options);
}
function assertSafeOutputs(report: ProviderQuota) {
  const response: QuotaAxiResponse = {
    schemaVersion: 6,
    generatedAt: new Date().toISOString(),
    providers: [withQuotaSemantics(report, new Date().toISOString())],
  };
  const outputs = [
    JSON.stringify(report),
    ...[false, true].flatMap((full) => [
      JSON.stringify(quotaJsonReport(response, full)),
      renderQuotaToon(redactedResponse(response, full), "quota-axi", full),
      renderQuotaTui(response, { columns: 100, colorDepth: "none", full }),
    ]),
    renderQuotaTui(response, { columns: 100, colorDepth: "none" }),
  ];
  for (const output of outputs) {
    for (const canary of [token, token.slice(0, 10), email, account])
      expect(output).not.toContain(canary);
  }
}
const failures = [
  {
    name: "transport",
    code: "provider_request_failed",
    respond: () => {
      throw new Error(secretText);
    },
  },
  {
    name: "malformed JSON",
    code: "invalid_json",
    respond: () => new Response(secretText),
  },
  {
    name: "truncated JSON",
    code: "invalid_json",
    respond: () => new Response(`{"secret":"${secretText}`),
  },
  {
    name: "stream failure",
    code: "provider_request_failed",
    respond: () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error(secretText));
          },
        }),
      ),
  },
  {
    name: "timeout",
    code: "provider_timeout",
    respond: () => {
      throw new DOMException(secretText, "AbortError");
    },
  },
  {
    name: "streamed oversize",
    code: "response_too_large",
    respond: () =>
      Response.json({
        padding: "x".repeat(PROVIDER_RESPONSE_LIMIT_BYTES),
        five_hour: { utilization: 10 },
        rate_limit: { primary_window: { used_percent: 10 } },
      }),
  },
  {
    name: "declared oversize",
    code: "response_too_large",
    respond: () =>
      new Response(new ReadableStream(), {
        headers: {
          "content-length": String(PROVIDER_RESPONSE_LIMIT_BYTES + 1),
        },
      }),
  },
];
describe("provider request safety", () => {
  for (const source of sources) {
    it.each(failures)(
      `${source} maps $name to safe diagnostics in every output tier`,
      async ({ code, respond }) => {
        const fetch = vi.fn(async () => respond());
        vi.stubGlobal("fetch", fetch);
        const report = await fetchSource(source);
        expect(fetch).toHaveBeenCalled();
        expect(report.state.error).toBe(code);
        expect(report.state.status).toBe("error");
        expect(report.windows).toEqual([]);
        expect(report.attempts).toContainEqual(
          expect.objectContaining({ status: "failed", error: code }),
        );
        assertSafeOutputs(report);
      },
    );
  }
  it.each(failures)(
    "keeps quota but rejects $name in a Claude profile response",
    async ({ code, respond }) => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string | URL | Request) =>
          String(url).endsWith("/profile")
            ? respond()
            : Response.json({
                five_hour: {
                  utilization: 20,
                  resets_at: new Date(Date.now() + 3600_000).toISOString(),
                },
              }),
        ),
      );
      const report = await fetchSource("claude-file");
      expect(report.state.status).toBe("fresh");
      expect(report.windows[0].percentRemaining).toBe(80);
      expect(report.account).toEqual({ identityStatus: "unverified" });
      expect(report.attempts).toContainEqual(
        expect.objectContaining({
          source: "oauth-profile",
          error: `identity_profile_${code}`,
        }),
      );
      assertSafeOutputs(report);
    },
  );
});
