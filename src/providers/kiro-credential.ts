import { statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { traceInput } from "../lib/input-trace.js";
import { execFileText } from "../lib/process.js";
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
        if ((presenceOnly && data.present === 1) || access) {
          sources.push({
            source,
            path,
            status: expired ? "expired" : "available",
            credentialPresent: true,
          });
          if (access) {
            const profile = literal(data.profile);
            // The profile's region is authoritative when the store omits it.
            const region =
              literal(data.region) ?? profile?.split(":")[3] ?? "us-east-1";
            if (
              ![
                "us-east-1",
                "eu-central-1",
                "us-gov-east-1",
                "us-gov-west-1",
              ].includes(region)
            ) {
              sources[sources.length - 1] = {
                source,
                path,
                status: "invalid",
                error: "kiro_region_unsupported",
                credentialPresent: true,
              };
              continue;
            }
            candidates.push({
              source,
              localState: expired ? "expired" : "valid",
              refreshable: data.refreshable === 1,
              credential: { access, profile, region },
            });
          }
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
  return typeof value === "string" &&
    value.trim() &&
    !value.includes("$") &&
    !value.startsWith("!") &&
    ![...value].some(
      (character) =>
        character.charCodeAt(0) <= 0x20 || character.charCodeAt(0) === 0x7f,
    )
    ? value
    : undefined;
}
