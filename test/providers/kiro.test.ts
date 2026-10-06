import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { kiroAdapter, normalizeKiroQuota } from "../../src/providers/kiro.js";
import {
  readKiroCredentials,
  kiroDatabasePath,
} from "../../src/providers/kiro-credential.js";
import { kiroReadingContextId } from "../../src/providers/kiro-cache-context.js";
import { withQuotaSemantics } from "../../src/interpretation.js";
import { writeCachedProviders } from "../../src/cache.js";
import { cacheFilePath } from "../../src/lib/fs.js";
import { coalesceVerifiedSubscriptions } from "../../src/providers/accounts.js";
import * as processUtils from "../../src/lib/process.js";
import { PROVIDER_RESPONSE_LIMIT_BYTES } from "../../src/lib/http.js";
import { renderQuotaToon, redactedResponse } from "../../src/render.js";
import type { ProviderQuota, QuotaAxiResponse } from "../../src/types.js";

const options = { allowKeychainPrompt: false, refreshCredentials: false };
const now = "2026-02-15T00:00:00.000Z";
const reset = Date.parse("2026-03-01T00:00:00.000Z") / 1000;
let directory: string;
let sql: ReturnType<typeof vi.spyOn>;
let fetchMock: ReturnType<typeof vi.fn>;
const originalDatabase = process.env.KIRO_CLI_DATABASE;
const originalCache = process.env.XDG_CACHE_HOME;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "quota-axi-kiro-"));
  process.env.KIRO_CLI_DATABASE = join(directory, "data.sqlite3");
  process.env.XDG_CACHE_HOME = directory;
  writeFileSync(process.env.KIRO_CLI_DATABASE, "synthetic database", {
    mode: 0o600,
  });
  delete process.env.KIRO_API_KEY;
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(now));
  sql = vi
    .spyOn(processUtils, "execFileText")
    .mockResolvedValue(JSON.stringify([credential()]));
  fetchMock = vi.fn().mockImplementation(async () => Response.json(usage()));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
  process.env.KIRO_CLI_DATABASE = originalDatabase;
  process.env.XDG_CACHE_HOME = originalCache;
  delete process.env.KIRO_API_KEY;
  delete process.env.KIRO_DATA_DIR;
  rmSync(directory, { recursive: true, force: true });
});

function credential(overrides: Record<string, unknown> = {}) {
  return {
    key: "kirocli:social:token",
    access: "synthetic-access",
    present: 1,
    accessValid: 1,
    expiry: "2026-02-16T00:00:00Z",
    refreshable: 1,
    profile: "arn:aws:kiro:us-east-1:000000000000:profile/example",
    ...overrides,
  };
}
function usage(
  item: Record<string, unknown> = {},
  root: Record<string, unknown> = {},
) {
  return {
    nextDateReset: reset,
    subscriptionInfo: { subscriptionTitle: "KIRO PRO" },
    userInfo: { userId: "example-account" },
    usageBreakdownList: [
      {
        resourceType: "CREDIT",
        currentUsage: 0,
        currentUsageWithPrecision: 125.5,
        usageLimit: 1,
        usageLimitWithPrecision: 1000,
        bonuses: [],
        overageCredits: [],
        ...item,
      },
    ],
    ...root,
  };
}

function responseFor(report: ProviderQuota): QuotaAxiResponse {
  return { generatedAt: now, schemaVersion: 5, providers: [report] };
}

describe("Kiro quota", () => {
  it("reports fractional monthly usage with a calendar-month cycle and spendPriority", async () => {
    const report = withQuotaSemantics(
      await kiroAdapter.fetchQuota(options),
      now,
    );
    expect(report.windows[0]).toMatchObject({
      id: "credit_monthly",
      percentUsed: 12.55,
      percentRemaining: 87.45,
      startsAt: "2026-02-01T00:00:00.000Z",
      resetsAt: "2026-03-01T00:00:00.000Z",
      pace: { cycleSeconds: 28 * 86400, cycleBasis: "starts_at_resets_at" },
    });
    expect(report.quotaSemantics?.effectiveAvailability[0]).toMatchObject({
      scope: "included:credit_monthly",
      status: "known",
      selection: { status: "known", spendPriority: 1.498 },
      runway: { status: "through_reset" },
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url.origin).toBe("https://management.us-east-1.kiro.dev");
    expect(url.pathname).toBe("/Get-Usage-Limits");
    expect(url.searchParams.get("origin")).toBe("KIRO_CLI");
    expect(init.headers.Authorization).toBe("Bearer synthetic-access");
    expect(init.headers).not.toHaveProperty("accept");
    expect(init.body).toBeUndefined();
    expect(init.method).toBeUndefined();
    expect(sql.mock.calls[0][1].slice(0, 3)).toEqual([
      "-readonly",
      "-json",
      process.env.KIRO_CLI_DATABASE,
    ]);
    const query = sql.mock.calls[0][1][3];
    expect(query).toContain("json_type(value, '$.refresh_token')");
    expect(query).not.toContain("json_extract(value, '$.refresh_token')");
    expect(query).not.toContain("SELECT value");
  });

  it("keeps usage and cycle unknown when fields are missing or invalid", () => {
    for (const currentUsageWithPrecision of [undefined, null, -1, "25", NaN]) {
      const normalized = normalizeKiroQuota(
        usage(
          { currentUsage: undefined, currentUsageWithPrecision },
          { nextDateReset: undefined },
        ),
      );
      expect(normalized.windows[0].percentUsed).toBeUndefined();
      expect(normalized.windows[0].startsAt).toBeUndefined();
      expect(normalized.windows[0].resetsAt).toBeUndefined();
    }
    const report = withQuotaSemantics(
      {
        provider: "kiro",
        windows: normalizeKiroQuota(usage({}, { nextDateReset: undefined }))
          .windows,
        state: { status: "fresh", stale: false },
      },
      now,
    );
    expect(
      report.quotaSemantics?.effectiveAvailability[0].selection?.status,
    ).toBe("unknown");
  });

  it("does not invent unlimited or zero-limit percentages", () => {
    for (const limit of [undefined, null, 0, -5, Infinity, 999999, 1000000]) {
      expect(
        normalizeKiroQuota(
          usage({ usageLimit: limit, usageLimitWithPrecision: limit }),
        ).windows[0].percentRemaining,
      ).toBeUndefined();
    }
  });

  it("keeps expiring bonus, trial and add-on pools separate from the included cycle", () => {
    const normalized = normalizeKiroQuota(
      usage({
        freeTrialInfo: {
          freeTrialStatus: "ACTIVE",
          currentUsage: 20,
          usageLimit: 100,
          freeTrialExpiry: reset,
        },
        bonuses: [
          {
            status: "ACTIVE",
            currentUsage: 10,
            usageLimit: 100,
            expiresAt: reset,
          },
          { status: "EXPIRED", currentUsage: 0, usageLimit: 100 },
        ],
        overageCredits: [
          { currentUsage: 25, usageLimit: 100, expiresAt: reset },
        ],
      }),
    );
    expect(normalized.windows.map((window) => window.percentRemaining)).toEqual(
      [87.45, 80, 90, 75],
    );
    for (const window of normalized.windows.slice(1)) {
      expect(window.startsAt).toBeUndefined();
      expect(window.resetsAt).toBeUndefined();
      expect(window.resetText).toContain("not a recurring reset");
    }
    const report = withQuotaSemantics(
      {
        provider: "kiro",
        windows: normalized.windows,
        state: { status: "fresh", stale: false },
      },
      now,
    );
    expect(
      report.quotaSemantics?.effectiveAvailability.map(
        (scope) => scope.boundedBy,
      ),
    ).toEqual(normalized.windows.map(({ id }) => [id]));
    expect(
      report.quotaSemantics?.effectiveAvailability[1].selection?.status,
    ).toBe("unknown");
  });

  it("omits pools whose vendor expiry has passed", () => {
    const result = normalizeKiroQuota(
      usage({
        overageCredits: [{ currentUsage: 0, usageLimit: 100, expiresAt: 1 }],
      }),
    );
    expect(result.windows).toHaveLength(1);
  });

  it("uses reported per-resource resets and clamps calendar month boundaries", () => {
    const date = "2026-03-31T00:00:00.000Z";
    expect(
      normalizeKiroQuota(usage({ nextDateReset: date })).windows[0],
    ).toMatchObject({ startsAt: "2026-02-28T00:00:00.000Z", resetsAt: date });
  });

  it("rejects malformed and duplicate quota shapes without guessing", () => {
    for (const raw of [
      null,
      {},
      { usageBreakdownList: {} },
      { usageBreakdownList: [null] },
    ])
      expect(() => normalizeKiroQuota(raw)).toThrow();
    expect(() =>
      normalizeKiroQuota(
        usage(
          {},
          {
            usageBreakdownList: [
              usage().usageBreakdownList[0],
              usage().usageBreakdownList[0],
            ],
          },
        ),
      ),
    ).toThrow("ambiguous");
  });

  it("tests stored-expired access read-only before reporting soft expiry", async () => {
    sql.mockResolvedValue(
      JSON.stringify([credential({ expiry: "2026-02-01T00:00:00Z" })]),
    );
    expect((await kiroAdapter.fetchQuota(options)).state.authStatus).toBe(
      "usable",
    );
    fetchMock.mockResolvedValue(new Response("", { status: 401 }));
    const rejected = await kiroAdapter.fetchQuota(options);
    expect(rejected.state).toMatchObject({
      status: "unavailable",
      authStatus: "expired_refreshable",
      reason: "credentials_expired",
      remedyCommand: "kiro-cli login",
    });
    expect(sql.mock.calls.every(([command]) => command === "sqlite3")).toBe(
      true,
    );
  });

  it.each([403, 429, 500])(
    "keeps HTTP %i transient without switching credentials",
    async (status) => {
      process.env.KIRO_API_KEY = "synthetic-api-key";
      fetchMock.mockResolvedValue(new Response("private-body", { status }));
      const result = await kiroAdapter.fetchQuota(options);
      expect(result.state.status).toBe(
        status === 429 ? "rate_limited" : "unavailable",
      );
      expect(fetchMock).toHaveBeenCalledOnce();
      expect(JSON.stringify(result)).not.toContain("private-body");
    },
  );

  it("treats the documented invalid-bearer 403 as definitive soft expiry", async () => {
    sql.mockResolvedValue(
      JSON.stringify([credential({ expiry: "2026-02-01T00:00:00Z" })]),
    );
    fetchMock.mockResolvedValue(
      Response.json(
        {
          __type: "com.amazon.aws.codewhisperer#AccessDeniedException",
          message: "The bearer token included in the request is invalid.",
          reason: null,
        },
        { status: 403 },
      ),
    );
    const report = await kiroAdapter.fetchQuota(options);
    expect(report.state).toMatchObject({
      status: "unavailable",
      authStatus: "expired_refreshable",
      reason: "credentials_expired",
      remedyCommand: "kiro-cli login",
    });
    expect(renderQuotaToon(responseFor(report), "quota-axi", true)).toContain(
      "kiro_auth_rejected_invalid_token",
    );
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(sql.mock.calls.every(([command]) => command === "sqlite3")).toBe(
      true,
    );
  });

  it.each([
    { expiry: "2026-02-16T00:00:00Z" },
    { expiry: "2026-02-01T00:00:00Z", refreshable: 0 },
  ])(
    "does not invent soft expiry for a rejected 403 with %j",
    async (stored) => {
      sql.mockResolvedValue(JSON.stringify([credential(stored)]));
      fetchMock.mockResolvedValue(
        Response.json(
          { message: "The bearer token included in the request is invalid." },
          { status: 403 },
        ),
      );
      const report = await kiroAdapter.fetchQuota(options);
      expect(report.state.status).toBe("auth_required");
      expect(report.state.authStatus).toBeUndefined();
      expect(report.state.reason).toBeUndefined();
      expect(report.state.remedyCommand).toBe("kiro-cli login");
    },
  );

  it("tries the next source after invalid-bearer 403 rejection", async () => {
    process.env.KIRO_API_KEY = "synthetic-api-key";
    fetchMock.mockResolvedValueOnce(
      Response.json(
        { message: "The bearer token included in the request is invalid." },
        { status: 403 },
      ),
    );
    const report = await kiroAdapter.fetchQuota(options);
    expect(report.state.status).toBe("fresh");
    expect(report.attempts?.[0].error).toBe("kiro_auth_rejected_invalid_token");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][1].headers.Authorization).toBe(
      "Bearer synthetic-api-key",
    );
  });

  it.each([
    "UNAUTHORIZED_CUSTOMIZATION_RESOURCE_ACCESS",
    "UNAUTHORIZED_WORKSPACE_CONTEXT_FEATURE_ACCESS",
  ])(
    "reports %s as an access denial without switching or expiry",
    async (reason) => {
      process.env.KIRO_API_KEY = "synthetic-api-key";
      sql.mockResolvedValue(
        JSON.stringify([credential({ expiry: "2026-02-01T00:00:00Z" })]),
      );
      fetchMock.mockResolvedValue(
        Response.json(
          { reason, message: "private policy detail" },
          { status: 403 },
        ),
      );
      const report = await kiroAdapter.fetchQuota(options);
      expect(report.state).toMatchObject({
        status: "error",
        error: "kiro_usage_policy_access_denied_contact_administrator",
      });
      expect(report.state.authStatus).toBeUndefined();
      expect(report.state.reason).toBeUndefined();
      expect(report.state.remedyCommand).toBeUndefined();
      expect(renderQuotaToon(responseFor(report), "quota-axi", true)).toContain(
        "policy_access_denied_contact_administrator",
      );
      expect(fetchMock).toHaveBeenCalledOnce();
    },
  );

  it.each([
    "not json",
    "null",
    "[]",
    "{}",
    JSON.stringify({
      nested: {
        message: "The bearer token included in the request is invalid.",
      },
    }),
    JSON.stringify({ reason: "INVALID_TOKEN" }),
    JSON.stringify({ reason: "EXPIRED_TOKEN" }),
    JSON.stringify({ reason: "FEATURE_NOT_SUPPORTED" }),
    JSON.stringify({ reason: "TEMPORARILY_SUSPENDED" }),
    JSON.stringify({
      reason: { code: "UNAUTHORIZED_CUSTOMIZATION_RESOURCE_ACCESS" },
    }),
    JSON.stringify({
      reason: "NEW_REASON",
      message: "The bearer token included in the request is invalid.",
    }),
    JSON.stringify({
      message:
        "The bearer token included in the request is invalid. Extra detail",
    }),
  ])("preserves an unknown 403 as transient for body %s", async (body) => {
    process.env.KIRO_API_KEY = "synthetic-api-key";
    fetchMock.mockResolvedValue(new Response(body, { status: 403 }));
    const report = await kiroAdapter.fetchQuota(options);
    expect(report.state).toMatchObject({
      status: "unavailable",
      error: "kiro_usage_forbidden",
    });
    expect(report.state.remedyCommand).toBeUndefined();
    expect(renderQuotaToon(responseFor(report), "quota-axi", true)).toContain(
      "kiro_usage_forbidden_unknown",
    );
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([false, true])(
    "bounds a 403 body with declared length %s",
    async (declared) => {
      process.env.KIRO_API_KEY = "synthetic-api-key";
      const body = JSON.stringify({
        message: "The bearer token included in the request is invalid.",
        padding: "x".repeat(PROVIDER_RESPONSE_LIMIT_BYTES),
      });
      fetchMock.mockResolvedValue(
        new Response(body, {
          status: 403,
          headers: declared ? { "content-length": String(body.length) } : {},
        }),
      );
      const report = await kiroAdapter.fetchQuota(options);
      expect(report.state.error).toBe("kiro_usage_forbidden");
      expect(report.attempts?.[0].error).toBe("kiro_usage_forbidden_unknown");
      expect(fetchMock).toHaveBeenCalledOnce();
    },
  );

  it("keeps an unreadable 403 body transient without exposing the read error", async () => {
    process.env.KIRO_API_KEY = "synthetic-api-key";
    fetchMock.mockResolvedValue(
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error("synthetic-private-read-error"));
          },
        }),
        { status: 403 },
      ),
    );
    const report = await kiroAdapter.fetchQuota(options);
    expect(report.state.error).toBe("kiro_usage_forbidden");
    expect(report.attempts?.[0].error).toBe("kiro_usage_forbidden_unknown");
    expect(JSON.stringify(report)).not.toContain(
      "synthetic-private-read-error",
    );
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    "UNAUTHORIZED_CUSTOMIZATION_RESOURCE_ACCESS",
    "synthetic-token-like-value",
  ])(
    "never renders or caches private 403 fields for reason %s",
    async (reason) => {
      writeCachedProviders([await kiroAdapter.fetchQuota(options)]);
      const privateValues = [
        "synthetic-token-like-value",
        "arn:aws:kiro:us-east-1:000000000000:profile/private-example",
        "private-account-example",
        "private@example.com",
      ];
      fetchMock.mockResolvedValue(
        Response.json(
          { reason, message: privateValues.join(" "), token: privateValues[0] },
          { status: 403 },
        ),
      );
      const report = await kiroAdapter.fetchQuota(options);
      const response = responseFor(report);
      writeCachedProviders([report]);
      const outputs = [
        JSON.stringify(response),
        JSON.stringify(redactedResponse(response, false)),
        renderQuotaToon(response, "quota-axi", false),
        renderQuotaToon(response, "quota-axi", true),
        readFileSync(cacheFilePath(), "utf8"),
      ];
      for (const output of outputs)
        for (const value of privateValues) expect(output).not.toContain(value);
    },
  );

  it("preserves the native source before an environment key despite advisory expiry", async () => {
    process.env.KIRO_API_KEY = "synthetic-api-key";
    sql.mockResolvedValue(
      JSON.stringify([credential({ expiry: "2026-02-01T00:00:00Z" })]),
    );
    const result = await kiroAdapter.fetchQuota(options);
    expect(result.state.authStatus).toBe("usable");
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe(
      "Bearer synthetic-access",
    );
    expect(result.attempts).toContainEqual({
      source: "env:KIRO_API_KEY",
      status: "skipped",
      credentialPresent: true,
    });
  });

  it("hands over from an expired source only after definitive rejection", async () => {
    process.env.KIRO_API_KEY = "synthetic-api-key";
    sql.mockResolvedValue(
      JSON.stringify([credential({ expiry: "2026-02-01T00:00:00Z" })]),
    );
    fetchMock.mockResolvedValueOnce(new Response("", { status: 401 }));
    expect((await kiroAdapter.fetchQuota(options)).state.authStatus).toBe(
      "usable",
    );
    expect(
      fetchMock.mock.calls.map(([, init]) => init.headers.Authorization),
    ).toEqual(["Bearer synthetic-access", "Bearer synthetic-api-key"]);
  });

  it("does not attach expired-auth metadata to a transient failure with an expired sibling", async () => {
    sql.mockResolvedValue(
      JSON.stringify([
        credential(),
        credential({
          key: "kirocli:odic:token",
          expiry: "2026-02-01T00:00:00Z",
        }),
      ]),
    );
    fetchMock.mockResolvedValue(new Response("", { status: 500 }));
    const result = await kiroAdapter.fetchQuota(options);
    expect(result.state).toMatchObject({
      status: "unavailable",
      error: "kiro_usage_unavailable",
    });
    expect(result.state.authStatus).not.toBe("expired_refreshable");
    expect(result.state.reason).not.toBe("credentials_expired");
    expect(result.state.remedyCommand).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("stops on transport or malformed-response failure", async () => {
    process.env.KIRO_API_KEY = "synthetic-api-key";
    fetchMock.mockRejectedValue(new Error("synthetic-access"));
    const result = await kiroAdapter.fetchQuota(options);
    expect(result.state.status).toBe("unavailable");
    expect(JSON.stringify(result)).not.toContain("synthetic-access");
    expect(fetchMock).toHaveBeenCalledOnce();
    fetchMock
      .mockClear()
      .mockResolvedValue(Response.json({ secret: "synthetic-access" }));
    expect((await kiroAdapter.fetchQuota(options)).state.status).toBe(
      "unavailable",
    );
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("hands over after definitive rejection and reports one quota for the selected source", async () => {
    process.env.KIRO_API_KEY = "synthetic-api-key";
    fetchMock
      .mockResolvedValueOnce(new Response("", { status: 401 }))
      .mockResolvedValueOnce(Response.json(usage()));
    const result = await kiroAdapter.fetchQuota(options);
    expect(result.windows).toHaveLength(1);
    expect(result.attempts).toContainEqual({
      source: "env:KIRO_API_KEY",
      status: "success",
      credentialPresent: true,
    });
  });

  it("coalesces verified subscription readings without summing windows", async () => {
    const native = await kiroAdapter.fetchQuota(options);
    process.env.KIRO_CLI_DATABASE = join(directory, "absent");
    process.env.KIRO_API_KEY = "synthetic-api-key";
    const alternate = await kiroAdapter.fetchQuota(options);
    expect(coalesceVerifiedSubscriptions([native, alternate])).toHaveLength(1);
    expect(
      coalesceVerifiedSubscriptions([native, alternate])[0].windows[0]
        .percentUsed,
    ).toBe(12.55);
    delete alternate.account;
    expect(coalesceVerifiedSubscriptions([native, alternate])).toHaveLength(2);
  });

  it("serializes only normalized quota, with opaque credential-scoped cache identity", async () => {
    const report = await kiroAdapter.fetchQuota(options);
    expect(kiroReadingContextId(report)).toMatch(/^[a-f0-9]{64}$/);
    writeCachedProviders([report]);
    const cached = readFileSync(cacheFilePath(), "utf8");
    expect(cached).not.toContain("synthetic-access");
    expect(cached).not.toContain("profile/example");
    sql.mockResolvedValue(
      JSON.stringify([credential({ access: "different-synthetic-access" })]),
    );
    expect(
      kiroReadingContextId(await kiroAdapter.fetchQuota(options)),
    ).not.toBe(kiroReadingContextId(report));
  });

  it("inspects auth metadata without access reads or HTTP", async () => {
    const auth = await kiroAdapter.inspectAuth(options);
    expect(auth.sources[0].status).toBe("available");
    expect(sql.mock.calls[0][1][3]).toContain("NULL AS access");
    expect(sql.mock.calls[0][1][3]).toContain("AS accessValid");
    expect(sql.mock.calls[0][1][3]).not.toContain(
      "json_extract(value, '$.access_token') AS access",
    );
    expect(fetchMock).not.toHaveBeenCalled();
    expect(JSON.stringify(auth)).not.toContain("synthetic-access");
  });

  it("projects literal validity in SQLite without returning access material", async () => {
    const database = new DatabaseSync(":memory:");
    try {
      database.exec("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)");
      const store = database.prepare(
        "INSERT OR REPLACE INTO auth_kv VALUES (?, ?)",
      );
      sql.mockImplementation(async (_command, args) =>
        JSON.stringify(database.prepare(args[3]).all()),
      );
      const whitespace = [
        9, 10, 11, 12, 13, 32, 160, 5760, 8192, 8193, 8194, 8195, 8196, 8197,
        8198, 8199, 8200, 8201, 8202, 8232, 8233, 8239, 8287, 12288, 65279,
      ];
      const values: unknown[] = [
        "synthetic-access",
        "!command",
        "${KEY}",
        "prefix$KEY",
        "",
        null,
        123,
        ...Array.from(
          { length: 33 },
          (_, i) => `synthetic${String.fromCharCode(i)}access`,
        ),
        "synthetic\x7faccess",
        ...whitespace.map((code) => String.fromCharCode(code)),
        "\u00a0synthetic-access", // Non-ASCII whitespace inside a nonblank literal is preserved.
      ];
      for (const access of values) {
        store.run(
          "kirocli:social:token",
          JSON.stringify({ access_token: access }),
        );
        const normal = await readKiroCredentials();
        const metadata = await readKiroCredentials(true);
        expect(metadata.sources[0].status).toBe(normal.sources[0].status);
        expect(metadata.candidates).toEqual([]);
        const projected = database
          .prepare(sql.mock.calls.at(-1)![1][3])
          .all()[0];
        expect(projected.access).toBeNull();
        expect(JSON.stringify(metadata)).not.toContain("synthetic-access");
      }
    } finally {
      database.close();
    }
  });

  it("keeps auth metadata validation consistent without selecting access material", async () => {
    for (const overrides of [
      { access: null, accessValid: 0 },
      { access: null, accessValid: 1, region: "example.com" },
      {
        access: null,
        accessValid: 1,
        profile: "arn:aws:kiro:unsupported:000000000000:profile/example",
      },
    ]) {
      sql.mockResolvedValue(JSON.stringify([credential(overrides)]));
      const auth = await kiroAdapter.inspectAuth(options);
      expect(auth.sources[0].status).toBe("invalid");
    }
    sql.mockResolvedValue(
      JSON.stringify([
        credential({
          access: null,
          region: undefined,
          profile: "arn:aws:kiro:eu-central-1:000000000000:profile/example",
        }),
      ]),
    );
    expect((await kiroAdapter.inspectAuth(options)).sources[0].status).toBe(
      "available",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("discovers the native Windows store and retains explicit override precedence", () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("win32");
    vi.stubEnv("LOCALAPPDATA", join(directory, "local-app-data"));
    expect(kiroDatabasePath()).toBe(process.env.KIRO_CLI_DATABASE);
    delete process.env.KIRO_CLI_DATABASE;
    process.env.KIRO_DATA_DIR = directory;
    expect(kiroDatabasePath()).toBe(join(directory, "data.sqlite3"));
    delete process.env.KIRO_DATA_DIR;
    expect(kiroDatabasePath()).toBe(
      join(directory, "local-app-data", "kiro-cli", "data.sqlite3"),
    );
  });

  it("distinguishes missing sqlite and broken credential stores from sign-out", async () => {
    sql.mockRejectedValue(
      Object.assign(new Error("private detail"), { code: "ENOENT" }),
    );
    expect((await kiroAdapter.fetchQuota(options)).state).toMatchObject({
      status: "error",
      error: "sqlite3_unavailable",
    });
    sql.mockResolvedValue("not json");
    expect((await kiroAdapter.fetchQuota(options)).state).toMatchObject({
      status: "error",
      error: "kiro_credentials_unreadable",
    });
  });

  it("rejects credential indirection and unapproved endpoint regions", async () => {
    for (const access of ["!command", "${KEY}", "bad\ntoken", ""]) {
      sql.mockResolvedValue(JSON.stringify([credential({ access })]));
      expect((await readKiroCredentials()).candidates).toHaveLength(0);
    }
    sql.mockResolvedValue(
      JSON.stringify([credential({ region: "example.com" })]),
    );
    expect((await kiroAdapter.fetchQuota(options)).state.error).toBe(
      "kiro_region_unsupported",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("honors the vendor data directory override", () => {
    delete process.env.KIRO_CLI_DATABASE;
    process.env.KIRO_DATA_DIR = directory;
    expect(kiroDatabasePath()).toBe(join(directory, "data.sqlite3"));
  });
});
