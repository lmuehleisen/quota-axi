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
  type CredentialSelection,
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
    let selection: CredentialSelection<ProviderQuota> = await selectCredential(
      [],
      attempt,
    );
    // Preserve source ownership order even when a store's expiry is advisory.
    for (const candidate of candidates) {
      const next = await selectCredential([candidate], attempt);
      selection = {
        ...next,
        refreshable: selection.refreshable || next.refreshable,
        results: [...selection.results, ...next.results],
      };
      if (next.outcome !== "all_rejected") break;
    }
    for (const candidate of candidates.slice(selection.results.length))
      selection.results.push({
        source: candidate.source,
        localState: candidate.localState,
        refreshable: candidate.refreshable,
        outcome: "not_tried",
      });
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
      selection.outcome === "all_rejected" &&
      selection.refreshable &&
      selection.results.some((result) => result.localState === "expired");
    const error =
      selection.forbiddenError ??
      (selection.transientError === "kiro_usage_forbidden_unknown"
        ? "kiro_usage_forbidden"
        : selection.transientError) ??
      (expired
        ? "kiro_credentials_expired"
        : (operational?.error ?? "kiro_auth_required"));
    const report = failedProvider({
      provider: "kiro",
      label: "Kiro",
      status:
        selection.outcome === "forbidden"
          ? "error"
          : selection.outcome === "transient"
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
      });
    if (
      selection.outcome === "all_rejected" &&
      selection.results.some(
        (result) =>
          result.outcome === "rejected" &&
          result.source.startsWith("kiro-cli-"),
      )
    )
      report.state.remedyCommand = "kiro-cli login";
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
    if (response.status === 403) {
      const category = await classifyKiroForbidden(response, signal);
      if (category === "invalid_token")
        return { kind: "rejected", error: "kiro_auth_rejected_invalid_token" };
      if (category === "policy_access_denied")
        return {
          kind: "forbidden",
          error: "kiro_usage_policy_access_denied_contact_administrator",
        };
      return { kind: "transient", error: "kiro_usage_forbidden_unknown" };
    }
    if (!response.ok)
      return {
        kind: "transient",
        error:
          response.status === 429
            ? "kiro_rate_limited"
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

type KiroForbiddenCategory =
  | "invalid_token"
  | "policy_access_denied"
  | "unknown";

async function classifyKiroForbidden(
  response: Response,
  signal: AbortSignal,
): Promise<KiroForbiddenCategory> {
  try {
    const bytes = await readBoundedResponseBody(
      response,
      signal,
      (code) => new Error(code),
    );
    // Reduce inputs to fixed categories/booleans before forming an object;
    // neither message text nor arbitrary reason strings survive the reviver.
    const raw = object(
      JSON.parse(new TextDecoder().decode(bytes), (key, value: unknown) => {
        if (key === "reason") {
          if (
            value === "UNAUTHORIZED_CUSTOMIZATION_RESOURCE_ACCESS" ||
            value === "UNAUTHORIZED_WORKSPACE_CONTEXT_FEATURE_ACCESS"
          )
            return "policy_access_denied";
          return value == null ? null : "unknown";
        }
        if (key === "message")
          return (
            value === "The bearer token included in the request is invalid."
          );
        return key === "" ? value : undefined;
      }),
    );
    // Vendor-generated CodeWhisperer AccessDeniedExceptionReason definitions:
    // https://github.com/aws/amazon-q-developer-cli/blob/main/crates/amzn-codewhisperer-client/src/types/_access_denied_exception_reason.rs
    if (raw?.reason === "policy_access_denied") return "policy_access_denied";
    // No invalid/expired-token reason code is established by that enum. AWS
    // documents this exact 403 message; match it only when reason is absent.
    // https://aws.amazon.com/tw/events/taiwan/techblogs/troubleshooting/
    if (raw && raw.reason == null && raw.message === true)
      return "invalid_token";
  } catch {
    // Malformed, oversized, or unreadable 403 bodies establish no auth verdict.
  }
  return "unknown";
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
