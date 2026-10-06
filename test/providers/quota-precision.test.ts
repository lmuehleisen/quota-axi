import { describe, expect, it } from "vitest";
import { normalizeClaudeApiUsage } from "../../src/providers/claude.js";
import { normalizeCodexUsage } from "../../src/providers/codex.js";
import {
  normalizeAgyQuotaSummary,
  normalizeAgyUserStatus,
} from "../../src/providers/agy.js";
import { withQuotaSemantics } from "../../src/interpretation.js";
import type { ProviderQuota } from "../../src/types.js";

const generatedAt = "2026-10-06T20:00:00Z";
const reset = "2026-10-06T21:00:00Z";
const normalizers = [
  {
    provider: "claude" as const,
    normalize: (used: number) =>
      normalizeClaudeApiUsage({
        five_hour: { utilization: used, resets_at: reset },
      }),
  },
  {
    provider: "claude" as const,
    normalize: (used: number) =>
      normalizeClaudeApiUsage({
        limits: [{ group: "session", percent: used, resets_at: reset }],
      }),
  },
  {
    provider: "codex" as const,
    normalize: (used: number) =>
      normalizeCodexUsage({
        rate_limit: {
          primary_window: {
            used_percent: used,
            reset_at: reset,
            limit_window_seconds: 18_000,
          },
        },
      }),
  },
  {
    provider: "codex" as const,
    normalize: (used: number) =>
      normalizeCodexUsage({
        rateLimits: {
          primary: {
            usedPercent: used,
            resetsAt: reset,
            windowDurationMins: 300,
          },
        },
      }),
  },
];
function report(
  provider: ProviderQuota["provider"],
  windows: ProviderQuota["windows"],
) {
  return withQuotaSemantics(
    { provider, windows, state: { status: "fresh", stale: false } },
    generatedAt,
  );
}

describe("quota precision and invalid observations", () => {
  for (const { provider, normalize } of normalizers) {
    it.each([99.49, 99.5, 99.9])(
      `${provider} preserves %s percent use through availability and runway`,
      (used) => {
        const result = normalize(used)!;
        expect(result.windows).toHaveLength(1);
        expect(result.windows[0].percentUsed).toBe(used);
        expect(result.windows[0].percentRemaining).toBe(100 - used);
        const scope = report(provider, result.windows).quotaSemantics!
          .effectiveAvailability[0];
        expect(scope.effectivePercentRemaining).toBe(100 - used);
        expect(scope.runway?.status).toBe("projected_exhaustion");
        expect(scope.selection?.status).toBe("known");
      },
    );
    it.each([-1, NaN, Infinity, -Infinity])(
      `${provider} leaves invalid use %s unmeasured`,
      (used) => {
        const result = normalize(used)!;
        expect(result.windows).toHaveLength(1);
        expect(result.windows[0].percentUsed).toBeUndefined();
        expect(result.windows[0].percentRemaining).toBeUndefined();
        const scope = report(provider, result.windows).quotaSemantics!
          .effectiveAvailability[0];
        expect(scope.status).toBe("unknown");
        expect(scope.runway?.status).toBe("unknown");
        expect(scope.selection?.status).toBe("unknown");
      },
    );
    it("bounds use above the limit to exhausted capacity", () => {
      const result = normalize(120)!;
      expect(result.windows[0].percentRemaining).toBe(0);
      expect(
        report(provider, result.windows).quotaSemantics!
          .effectiveAvailability[0].runway?.status,
      ).toBe("exhausted_now");
    });
  }

  const agySummary = (fraction: number, resetTime: unknown = reset) =>
    normalizeAgyQuotaSummary({
      groups: [
        {
          displayName: "Gemini Models",
          buckets: [
            {
              bucketId: "gemini-5h",
              window: "5h",
              remainingFraction: fraction,
              resetTime,
            },
          ],
        },
      ],
    });
  const agyModel = (fraction: number) =>
    normalizeAgyUserStatus({
      userStatus: {
        cascadeModelConfigData: {
          clientModelConfigs: [
            {
              label: "Gemini",
              modelOrAlias: { model: "gemini" },
              quotaInfo: { remainingFraction: fraction, resetTime: reset },
            },
          ],
        },
      },
    });
  for (const normalize of [agySummary, agyModel]) {
    it.each([0.004, 0.00004, 0.000000004])(
      "preserves agy remaining fraction %s",
      (fraction) => {
        const result = normalize(fraction)!;
        expect(result.windows).toHaveLength(1);
        expect(result.windows[0].percentRemaining).toBe(fraction * 100);
        const semantics = report("agy", result.windows).quotaSemantics!;
        const scope = semantics.effectiveAvailability[0];
        if (normalize === agySummary) {
          expect(scope.effectivePercentRemaining).toBe(fraction * 100);
          expect(scope.runway?.status).not.toBe("exhausted_now");
        } else {
          expect(semantics.status).toBe("unknown");
          expect(semantics.unresolvedWindowIds).toEqual([result.windows[0].id]);
        }
      },
    );
    it.each([-1, Infinity, NaN, 2])(
      "leaves invalid agy fractions %s unmeasured",
      (fraction) => {
        const result = normalize(fraction)!;
        expect(result.windows[0].percentRemaining).toBeUndefined();
        const semantics = report("agy", result.windows).quotaSemantics!;
        expect(
          normalize === agySummary
            ? semantics.effectiveAvailability[0].status
            : semantics.status,
        ).toBe("unknown");
      },
    );
  }
  it.each([1e20, -1e20, Number.MAX_VALUE])(
    "keeps siblings when reset %s is unrepresentable",
    (value) => {
      const codex = normalizeCodexUsage({
        rate_limit: {
          primary_window: {
            used_percent: 20,
            reset_at: value,
            reset_after_seconds: value,
          },
          secondary_window: { used_percent: 30, reset_at: reset },
        },
      })!;
      expect(codex.windows).toHaveLength(2);
      expect(codex.windows[0].resetsAt).toBeUndefined();
      expect(codex.windows[1].resetsAt).toBe("2026-10-06T21:00:00.000Z");
      expect(agySummary(0.5, value)?.windows[0].resetsAt).toBeUndefined();
    },
  );
});
