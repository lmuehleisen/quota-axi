import { providerFetch, readBoundedResponseBody } from "../lib/http.js";
import { calendarMonthsBefore } from "../lib/time.js";
import type {
  ProviderAdapter,
  ProviderQuota,
  QuotaWindow,
  SourceAttempt,
} from "../types.js";
import { failedProvider, sourceNames, successProvider } from "./common.js";
import {
  selectCredential,
  type AttemptOutcome,
  type CredentialCandidate,
} from "./credential-selection.js";
import { readKiroCredentials, type KiroCredential } from "./kiro-credential.js";
import { stampKiroContext } from "./kiro-cache-context.js";

export const kiroAdapter: ProviderAdapter = {
  id: "kiro",
  label: "Kiro",
  inspectAuth: async () => ({
    provider: "kiro",
    sources: (await readKiroCredentials(true)).sources,
  }),
  fetchQuota: async () => {
    const { candidates, sources } = await readKiroCredentials();
    const selection = await selectCredential(candidates, attempt);
    const attempts: SourceAttempt[] = sources.map((source) => {
      const result = selection.results.find(
        (candidate) => candidate.source === source.source,
      );
      return {
        source: source.source,
        status:
          result?.outcome === "quota"
            ? "success"
            : result && result.outcome !== "not_tried"
              ? "failed"
              : "skipped",
        credentialPresent: source.credentialPresent,
        ...(result?.error || source.error
          ? { error: result?.error ?? source.error }
          : {}),
      };
    });
    if (selection.result) {
      const report = selection.result;
      report.attempts = attempts;
      report.state.sourcesTried = sourceNames(attempts);
      return report;
    }
    const operational = sources.find(({ status }) =>
      ["error", "invalid", "unsupported"].includes(status),
    );
    const expired =
      selection.refreshable &&
      selection.results.some((result) => result.localState === "expired");
    const error =
      selection.transientError ??
      (expired
        ? "kiro_credentials_expired"
        : (operational?.error ?? "kiro_auth_required"));
    const report = failedProvider({
      provider: "kiro",
      label: "Kiro",
      status:
        selection.outcome === "transient"
          ? error === "kiro_rate_limited"
            ? "rate_limited"
            : "unavailable"
          : expired
            ? "unavailable"
            : operational
              ? "error"
              : "auth_required",
      error,
      attempts,
      sourcesTried: sourceNames(attempts),
      retryAfter: selection.retryAfter,
    });
    if (expired)
      Object.assign(report.state, {
        authStatus: "expired_refreshable",
        reason: "credentials_expired",
        remedyCommand: "kiro-cli login",
      });
    return report;
  },
};

async function attempt(
  candidate: CredentialCandidate<KiroCredential>,
): Promise<AttemptOutcome<ProviderQuota>> {
  const { access, profile, region } = candidate.credential;
  const url = new URL(`https://management.${region}.kiro.dev/Get-Usage-Limits`);
  url.searchParams.set("origin", "KIRO_CLI");
  if (profile) url.searchParams.set("profileArn", profile);
  const signal = AbortSignal.timeout(15_000);
  try {
    const response = await providerFetch(url, {
      headers: {
        Authorization: `Bearer ${access}`,
      },
      signal,
    });
    if (response.status === 401)
      return { kind: "rejected", error: "kiro_auth_rejected" };
    // 403 can mean an admin-managed plan does not expose usage, not sign-out.
    if (!response.ok)
      return {
        kind: "transient",
        error:
          response.status === 429
            ? "kiro_rate_limited"
            : response.status === 403
              ? "kiro_usage_forbidden"
              : "kiro_usage_unavailable",
      };
    const bytes = await readBoundedResponseBody(
      response,
      signal,
      (code) => new Error(code),
    );
    const normalized = normalizeKiroQuota(
      JSON.parse(new TextDecoder().decode(bytes)),
    );
    const report = successProvider({
      provider: "kiro",
      label: "Kiro",
      source: "api",
      ...normalized,
      refreshedAt: new Date().toISOString(),
      sourcesTried: [candidate.source],
    });
    report.state.authStatus = "usable";
    stampKiroContext(report, candidate.source, region, profile, access);
    return { kind: "quota", result: report };
  } catch {
    return { kind: "transient", error: "kiro_usage_unavailable" };
  }
}

/** Kiro CLI 2.24's Get-Usage-Limits schema; each pool is reported separately. */
export function normalizeKiroQuota(
  raw: unknown,
): Pick<ProviderQuota, "windows" | "plan" | "account"> {
  const root = object(raw);
  if (!root || !Array.isArray(root.usageBreakdownList))
    throw new Error("kiro_usage_malformed");
  const windows: QuotaWindow[] = [];
  for (const [index, value] of root.usageBreakdownList.entries()) {
    const item = object(value);
    if (!item) throw new Error("kiro_usage_malformed");
    const resource =
      typeof item.resourceType === "string"
        ? item.resourceType.toLowerCase().replace(/[^a-z0-9]+/g, "_")
        : `resource_${index}`;
    const id = `${resource}_monthly`;
    const reset = timestamp(item.nextDateReset ?? root.nextDateReset);
    const monthly = pool(id, `${resource} monthly`, item, "monthly");
    if (reset) {
      monthly.resetsAt = reset;
      // Kiro documents calendar billing months, never a fixed 30-day period.
      monthly.startsAt = calendarMonthsBefore(reset, 1);
    }
    windows.push(monthly);
    const trial = object(item.freeTrialInfo);
    if (
      trial?.freeTrialStatus === "ACTIVE" &&
      !expiredPool(trial.freeTrialExpiry)
    )
      windows.push({
        ...pool(`${resource}_trial`, `${resource} trial`, trial, "credits"),
        resetText: expiryText(trial.freeTrialExpiry),
      });
    if (Array.isArray(item.bonuses))
      item.bonuses.forEach((value, i) => {
        const bonus = object(value);
        if (
          bonus &&
          ["ACTIVE", "EXHAUSTED"].includes(String(bonus.status)) &&
          !expiredPool(bonus.expiresAt)
        )
          windows.push({
            ...pool(
              `${resource}_bonus_${i + 1}`,
              `${resource} bonus ${i + 1}`,
              bonus,
              "credits",
            ),
            resetText: expiryText(bonus.expiresAt),
          });
      });
    if (Array.isArray(item.overageCredits))
      item.overageCredits.forEach((value, i) => {
        const extra = object(value);
        if (extra && !expiredPool(extra.expiresAt))
          windows.push({
            ...pool(
              `${resource}_addon_${i + 1}`,
              `${resource} add-on ${i + 1}`,
              extra,
              "credits",
            ),
            resetText: expiryText(extra.expiresAt),
          });
      });
  }
  if (new Set(windows.map(({ id }) => id)).size !== windows.length)
    throw new Error("kiro_usage_ambiguous");
  const title = object(root.subscriptionInfo)?.subscriptionTitle;
  const accountId = object(root.userInfo)?.userId;
  return {
    windows,
    ...(typeof title === "string" && title ? { plan: title } : {}),
    ...(typeof accountId === "string" && accountId
      ? { account: { accountId, identityStatus: "verified" as const } }
      : {}),
  };
}

function pool(
  id: string,
  label: string,
  value: Record<string, unknown>,
  kind: QuotaWindow["kind"],
): QuotaWindow {
  const used = number(value.currentUsageWithPrecision ?? value.currentUsage);
  const limit = number(value.usageLimitWithPrecision ?? value.usageLimit);
  const percentUsed =
    used !== undefined && limit !== undefined && limit > 0 && limit < 999999
      ? Math.min(100, (used / limit) * 100)
      : undefined;
  return {
    id,
    label,
    kind,
    ...(percentUsed === undefined
      ? {}
      : { percentUsed, percentRemaining: 100 - percentUsed }),
  };
}
function number(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : undefined;
}
function timestamp(value: unknown): string | undefined {
  const ms =
    typeof value === "number"
      ? value * 1000
      : typeof value === "string"
        ? Date.parse(value)
        : NaN;
  return Number.isFinite(ms) && Math.abs(ms) <= 8.64e15
    ? new Date(ms).toISOString()
    : undefined;
}
function expiryText(value: unknown): string | undefined {
  const expiry = timestamp(value);
  return expiry ? `Expires ${expiry}; not a recurring reset` : undefined;
}
function expiredPool(value: unknown): boolean {
  const expiry = timestamp(value);
  return expiry !== undefined && Date.parse(expiry) <= Date.now();
}
function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
