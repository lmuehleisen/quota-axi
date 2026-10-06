import { createHash } from "node:crypto";
import type { ProviderQuota } from "../types.js";

const CONTEXT = Symbol("kiroContext");
type StampedQuota = ProviderQuota & { [CONTEXT]?: string };

export function stampKiroContext(
  provider: ProviderQuota,
  source: string,
  region: string,
  profile: string | undefined,
  access: string,
): void {
  (provider as StampedQuota)[CONTEXT] = createHash("sha256")
    .update(
      JSON.stringify([
        "kiro-v1",
        source,
        region,
        profile,
        createHash("sha256").update(access).digest("hex"),
      ]),
    )
    .digest("hex");
}

/** Written from the answering credential only; never read secrets for cache lookup. */
export function kiroReadingContextId(
  provider: ProviderQuota,
): string | undefined {
  return (provider as StampedQuota)[CONTEXT];
}
