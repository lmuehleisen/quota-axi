import { statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { traceInput } from "../lib/input-trace.js";
import { execFileText } from "../lib/process.js";
import { usableLiteralSecret } from "../lib/secret.js";
import type { AuthSourceReport } from "../types.js";
import type { CredentialCandidate } from "./credential-selection.js";

export type KiroCredential = {
  access: string;
  profile?: string;
  region: string;
};
export type KiroCredentials = {
  candidates: CredentialCandidate<KiroCredential>[];
  sources: AuthSourceReport[];
};

const STORES = [
  ["kirocli:social:token", "kiro-cli-social"],
  ["kirocli:odic:token", "kiro-cli-oidc"],
  ["kirocli:external-idp:token", "kiro-cli-external-idp"],
] as const;

export function kiroDatabasePath(): string {
  if (process.env.KIRO_CLI_DATABASE) return process.env.KIRO_CLI_DATABASE;
  if (process.env.KIRO_DATA_DIR)
    return join(process.env.KIRO_DATA_DIR, "data.sqlite3");
  if (process.platform === "win32")
    return join(
      process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local"),
      "kiro-cli",
      "data.sqlite3",
    );
  return process.platform === "darwin"
    ? join(
        homedir(),
        "Library",
        "Application Support",
        "kiro-cli",
        "data.sqlite3",
      )
    : join(
        process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"),
        "kiro-cli",
        "data.sqlite3",
      );
}

/** SQLite projects only access material and refresh presence, never its value. */
export async function readKiroCredentials(
  presenceOnly = false,
): Promise<KiroCredentials> {
  const candidates: KiroCredentials["candidates"] = [];
  const sources: AuthSourceReport[] = [];
  const path = kiroDatabasePath();
  traceInput(path);
  traceInput(`${path}-wal`);
  let databaseStatus: "present" | "missing" | "error";
  try {
    databaseStatus = statSync(path).isFile() ? "present" : "error";
  } catch (error) {
    databaseStatus = object(error)?.code === "ENOENT" ? "missing" : "error";
  }
  if (databaseStatus === "missing") {
    sources.push({
      source: "kiro-cli",
      status: "missing",
      credentialPresent: false,
    });
  } else if (databaseStatus === "error") {
    sources.push({
      source: "kiro-cli",
      path,
      status: "error",
      error: "kiro_credentials_unreadable",
      credentialPresent: true,
    });
  } else {
    try {
      const query = `SELECT key,
        ${presenceOnly ? "NULL" : "json_extract(value, '$.access_token')"} AS access,
        json_type(value, '$.access_token') IS NOT NULL AS present,
        json_type(value, '$.access_token') = 'text'
          AND length(trim(json_extract(value, '$.access_token'),
            char(9,10,11,12,13,32,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288,65279))) > 0
          AND instr(json_extract(value, '$.access_token'), '$') = 0
          AND substr(json_extract(value, '$.access_token'), 1, 1) != '!'
          AND instr(json_extract(value, '$.access_token'), char(0)) = 0
          AND json_extract(value, '$.access_token') NOT GLOB
            '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,127) || ']*'
          AS accessValid,
        json_extract(value, '$.expires_at') AS expiry,
        json_type(value, '$.refresh_token') IS NOT NULL AS refreshable,
        json_extract(value, '$.profile_arn') AS profile,
        json_extract(value, '$.region') AS region
        FROM auth_kv WHERE key IN ('kirocli:social:token', 'kirocli:odic:token', 'kirocli:external-idp:token')`;
      const output = await execFileText(
        "sqlite3",
        ["-readonly", "-json", path, query],
        5_000,
        { maxBufferBytes: 64 * 1024 },
      );
      const rows: unknown = output.trim() ? JSON.parse(output) : [];
      if (!Array.isArray(rows)) throw new Error("invalid");
      for (const [key, source] of STORES) {
        const row = rows.find((value) => object(value)?.key === key);
        const data = object(row);
        if (!data) continue;
        const expiry =
          typeof data.expiry === "string" ? Date.parse(data.expiry) : NaN;
        const expired = Number.isFinite(expiry) && expiry <= Date.now();
        const access = literal(data.access);
        const profile = literal(data.profile);
        // The profile's region is authoritative when the store omits it.
        const region =
          literal(data.region) ?? profile?.split(":")[3] ?? "us-east-1";
        if (presenceOnly ? data.accessValid === 1 : access) {
          if (
            ![
              "us-east-1",
              "eu-central-1",
              "us-gov-east-1",
              "us-gov-west-1",
            ].includes(region)
          ) {
            sources.push({
              source,
              path,
              status: "invalid",
              error: "kiro_region_unsupported",
              credentialPresent: true,
            });
            continue;
          }
          sources.push({
            source,
            path,
            status: expired ? "expired" : "available",
            credentialPresent: true,
          });
          if (!presenceOnly && access)
            candidates.push({
              source,
              localState: expired ? "expired" : "valid",
              refreshable: data.refreshable === 1,
              credential: { access, profile, region },
            });
        } else {
          sources.push({
            source,
            path,
            status: "invalid",
            error: "kiro_credentials_invalid",
            credentialPresent: true,
          });
        }
      }
      if (!sources.length)
        sources.push({
          source: "kiro-cli",
          path,
          status: "missing",
          credentialPresent: false,
        });
    } catch (error) {
      const missingSqlite = object(error)?.code === "ENOENT";
      sources.push({
        source: "kiro-cli",
        path,
        status: "error",
        error: missingSqlite
          ? "sqlite3_unavailable"
          : "kiro_credentials_unreadable",
        credentialPresent: true,
      });
    }
  }
  const key = process.env.KIRO_API_KEY;
  if (key !== undefined) {
    const access = literal(key);
    sources.push({
      source: "env:KIRO_API_KEY",
      status: access ? "available" : "invalid",
      credentialPresent: true,
      ...(access ? {} : { error: "kiro_api_key_invalid" }),
    });
    if (access && !presenceOnly)
      candidates.push({
        source: "env:KIRO_API_KEY",
        localState: "valid",
        credential: { access, region: "us-east-1" },
      });
  } else
    sources.push({
      source: "env:KIRO_API_KEY",
      status: "missing",
      credentialPresent: false,
    });
  return { candidates, sources };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function literal(value: unknown): string | undefined {
  const secret = usableLiteralSecret(value);
  return secret && !secret.includes(" ") ? secret : undefined;
}
