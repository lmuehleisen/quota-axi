import { homedir } from "node:os";
import { join } from "node:path";
import {
  deleteCachedProvider as deleteCachedProviderFromDisk,
  readCachedMuseProvider as readCachedProviderFromDisk,
} from "../cache.js";
import { collapseHome, readBoundedFile } from "../lib/fs.js";
import { providerFetch, readBoundedResponseBody } from "../lib/http.js";
import { usableLiteralSecret } from "../lib/secret.js";
import { retryAfterToIso } from "../lib/time.js";
import type {
  AuthProviderReport,
  AuthSourceReport,
  ProviderAdapter,
  ProviderAuthStatus,
  ProviderOptions,
  ProviderQuota,
  ProviderStatus,
  QuotaWindow,
  SourceAttempt,
} from "../types.js";
import { VERSION } from "../version.js";
import { servableStaleWindows, servableUntrustedWindowIds } from "./common.js";
import {
  selectCredential,
  type AttemptOutcome,
  type CandidateResult,
  type CredentialCandidate,
} from "./credential-selection.js";
import {
  clearMuseReadingContextId,
  museCacheContextId,
  publishMuseReadingContextId,
} from "./muse-cache-context.js";
import {
  isMuseKeychainSourceSupported,
  MUSE_KEYCHAIN_SOURCE,
  readMuseKeychainCredential,
} from "./muse-keychain-credential.js";
import {
  createFileMuseKeyReadLedger,
  MUSE_KEY_READ_INTERVAL_MS,
  type MuseEmptyQuota,
  type MuseKeyRead,
  type MuseKeyReadClaim,
  type MuseKeyReadLedger,
} from "./muse-read-gate.js";

export const MUSE_API_ORIGIN = "https://api.meta.ai";
export const MUSE_KEY_PATH = "/muse-code/key";
/** The Muse CLI sends this on every mint, including startup `{ onboard: false }`. */
export const MUSE_API_VERSION = "1.0.0";

/**
 * The OpenAI-compatible inference endpoint. The free `/muse-code/key` read
 * omits `subs_usage` while the five-hour window is idle, so when that read
 * returns no usable usage this streamed response carries the subscription's
 * windows in a `response.subscription_usage` event. This is a billed call -
 * the smallest the API allows - and runs only as the documented fallback; see
 * the Muse exception in AGENTS.md / README Provider notes.
 */
export const MUSE_RESPONSES_PATH = "/v1/responses";
/** Spark is the model the Muse Code subscription bills against. */
export const MUSE_PING_MODEL = "muse-spark-1.3";
/** The API floor: `max_output_tokens` must be >= 16, so the ping cannot be cheaper. */
export const MUSE_PING_MAX_OUTPUT_TOKENS = 16;
/** The SSE event whose payload carries the subscription window usage. */
const MUSE_SUBSCRIPTION_USAGE_EVENT = "response.subscription_usage";

export const MUSE_AUTH_FILE_SOURCE = "muse:auth.json";
export const MUSE_API_KEY_SOURCE = "env:META_API_KEY";
/** Marks, in `attempts`/`sourcesTried`, that the billed usage ping was used. */
export const MUSE_USAGE_PING_SOURCE = "muse:usage-ping";

/**
 * Ownership-stability order. The Muse CLI's own sign-in store comes first -
 * the token in its `auth.json` on Linux, then the macOS Keychain item that
 * `storage: "keychain"` records point to - because it is the credential the
 * CLI itself sends to the key endpoint at startup, so it names the
 * subscription a live Muse session draws on. `META_API_KEY` is the explicitly
 * exported alternative and is consulted only when the CLI's store is absent or
 * its token is rejected.
 */
export const MUSE_SOURCE_ORDER = [
  MUSE_AUTH_FILE_SOURCE,
  MUSE_KEYCHAIN_SOURCE,
  MUSE_API_KEY_SOURCE,
] as const;

export type MuseSourceName = (typeof MUSE_SOURCE_ORDER)[number];

const LABEL = "Muse";
const OPERATION_DEADLINE_MS = 15_000;
const AUTH_FILE_LIMIT_BYTES = 64 * 1024;
const USER_AGENT = `quota-axi/${VERSION}`;
const FIVE_HOUR_MINUTES = 300;
const FIVE_HOURS_SECONDS = 18_000;
const WEEK_SECONDS = 604_800;

/**
 * The only response keys that survive parsing. The key endpoint's body also
 * carries the account's Model API `api_key` and account fields; a JSON reviver
 * drops every key outside this set while the body is parsed, so those values
 * never reach a JavaScript object, an error, the cache, or any output.
 */
const RESPONSE_KEYS = new Set([
  "is_subs_active",
  "subs_tier_name",
  "subs_usage",
  "window",
  "weekly",
  "used_percent",
  "window_duration_mins",
  "resets_at",
]);

/**
 * The only keys that survive parsing a `/v1/responses` SSE event. The usage
 * ping's stream also carries generated model output and request metadata; this
 * reviver keeps only the subscription window shape, so no model text, token
 * count, or account field reaches an object, the cache, or any output.
 */
const RESPONSES_EVENT_KEYS = new Set([
  "type",
  "subscription",
  "window",
  "weekly",
  "used_percent",
  "window_duration_mins",
  "resets_at",
]);

/**
 * The only `auth.json` keys that survive parsing. `refresh_token` survives as
 * `true` - presence decides soft expiry versus sign-out, and its value is never
 * held, read, or exchanged. `storage` survives so a `keychain` pointer can
 * route the lookup to the Keychain source instead of reporting a broken file.
 * `api_key` survives because it is the minted inference key the billed usage
 * ping fallback sends as a bearer; it is used only for that request and is
 * never logged, cached, or rendered.
 */
const AUTH_FILE_KEYS = new Set([
  "providers",
  "meta",
  "access_token",
  "refresh_token",
  "storage",
  "api_key",
]);

export type MuseLocalResolution =
  | {
      status: "resolved";
      credential: string;
      refreshable: boolean;
      /**
       * The minted inference key, when the store carries one. Used only as the
       * bearer for the billed usage-ping fallback; never logged or cached.
       */
      pingKey?: string;
    }
  | { status: "absent" }
  | { status: "structurally_invalid"; error: string }
  | { status: "read_error"; error: string }
  | { status: "skipped"; error: string };

export type MuseCredentialSource = {
  name: MuseSourceName;
  /** Display location for `auth`; never a credential value. */
  location(): string;
  resolve(
    options: Pick<ProviderOptions, "allowKeychainPrompt">,
    presenceOnly?: boolean,
  ): Promise<MuseLocalResolution>;
};

export type NormalizedMusePayload = {
  plan?: string;
  windows: QuotaWindow[];
  untrustedWindowIds: string[];
};

type MuseDependencies = {
  sources: readonly MuseCredentialSource[];
  fetch: typeof globalThis.fetch;
  readCachedProvider: (contextId: string) => ProviderQuota | undefined;
  deleteCachedProvider: () => void;
  ledger: MuseKeyReadLedger;
  now: () => number;
  deadlineMs: number;
};

type MuseFailureOptions = {
  status?: ProviderStatus;
  staleEligible?: boolean;
  definitiveAuth?: boolean;
  authUsable?: boolean;
  retryAfter?: string;
};

type MuseCandidate = {
  credential: string;
  contextId: string;
  pingKey?: string;
};

type MuseReading =
  | {
      kind: "fresh";
      payload: NormalizedMusePayload;
      refreshedAt: number;
      /** Set when the billed usage ping was fired, with its outcome. */
      ping?: "success" | "failed";
    }
  | { kind: "reused"; snapshot: ProviderQuota };

export function museAuthFilePath(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): string {
  return join(
    environment.XDG_CONFIG_HOME || join(homedir(), ".config"),
    "muse",
    "auth.json",
  );
}

/**
 * The Muse CLI's sign-in store. Only `providers.meta.access_token` is read, and
 * `refresh_token` only for presence. quota-axi never writes this file, never
 * refreshes the token, and never stores the key the endpoint returns.
 */
export function createMuseAuthFileSource(
  path: () => string = () => museAuthFilePath(),
  readFile: (
    path: string,
    maxBytes: number,
  ) => Promise<Buffer> = readBoundedFile,
): MuseCredentialSource {
  return {
    name: MUSE_AUTH_FILE_SOURCE,
    location: () => collapseHome(path()),
    async resolve() {
      let bytes: Buffer;
      try {
        bytes = await readFile(path(), AUTH_FILE_LIMIT_BYTES);
      } catch (error) {
        return errorCode(error) === "ENOENT"
          ? { status: "absent" }
          : { status: "read_error", error: "muse_auth_read_error" };
      }
      if (bytes.byteLength > AUTH_FILE_LIMIT_BYTES)
        return { status: "structurally_invalid", error: "muse_auth_too_large" };
      let root: unknown;
      try {
        root = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(bytes),
          (key, value: unknown) => {
            if (key === "" || AUTH_FILE_KEYS.has(key))
              return key === "refresh_token" ? true : value;
            return undefined;
          },
        );
      } catch {
        return { status: "structurally_invalid", error: "muse_auth_invalid" };
      }
      const store = objectValue(root);
      if (!store)
        return { status: "structurally_invalid", error: "muse_auth_invalid" };
      if (store.providers === undefined) return { status: "absent" };
      const providers = objectValue(store.providers);
      if (!providers)
        return { status: "structurally_invalid", error: "muse_auth_invalid" };
      if (providers.meta === undefined) return { status: "absent" };
      const meta = objectValue(providers.meta);
      if (!meta)
        return {
          status: "structurally_invalid",
          error: "muse_meta_entry_invalid",
        };
      const credential = usableLiteralSecret(meta.access_token);
      if (credential === undefined) {
        // `storage: "keychain"` with no token in the file is the macOS layout:
        // the credential lives in the Keychain source's item, so the file is a
        // pointer, not a broken store.
        if (meta.storage === "keychain" && isMuseKeychainSourceSupported())
          return { status: "absent" };
        return {
          status: "structurally_invalid",
          error: "muse_access_token_invalid",
        };
      }
      return {
        status: "resolved",
        credential,
        refreshable: Object.hasOwn(meta, "refresh_token"),
        ...(usableLiteralSecret(meta.api_key) !== undefined
          ? { pingKey: usableLiteralSecret(meta.api_key) }
          : {}),
      };
    },
  };
}

/**
 * The macOS Keychain item the Muse CLI's `storage: "keychain"` records point
 * to. Presence is free; the value read is gated by `--allow-keychain-prompt`
 * or the recorded grant marker, like the Claude and Cursor CLI sources.
 */
export function createMuseKeychainSource(): MuseCredentialSource {
  return {
    name: MUSE_KEYCHAIN_SOURCE,
    location: () => "Keychain ai.meta.dev.credentials",
    resolve: (options, presenceOnly) =>
      readMuseKeychainCredential(options, presenceOnly === true),
  };
}

/** The explicitly exported `META_API_KEY`, read on the same footing as a stored login. */
export function createMuseApiKeySource(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): MuseCredentialSource {
  return {
    name: MUSE_API_KEY_SOURCE,
    location: () => "META_API_KEY",
    resolve() {
      const raw = environment.META_API_KEY;
      // A blank variable selects nothing rather than reporting a broken key.
      if (raw === undefined || raw.trim().length === 0)
        return Promise.resolve({ status: "absent" });
      const credential = usableLiteralSecret(raw);
      return Promise.resolve(
        credential === undefined
          ? { status: "structurally_invalid", error: "meta_api_key_invalid" }
          : { status: "resolved", credential, refreshable: false },
      );
    },
  };
}

export function createMuseAdapter(
  overrides: Partial<MuseDependencies> = {},
): ProviderAdapter {
  const dependencies: MuseDependencies = {
    sources: [
      createMuseAuthFileSource(),
      createMuseKeychainSource(),
      createMuseApiKeySource(),
    ],
    fetch: providerFetch,
    readCachedProvider: readCachedProviderFromDisk,
    deleteCachedProvider: () => deleteCachedProviderFromDisk("muse"),
    ledger: createFileMuseKeyReadLedger(),
    now: Date.now,
    deadlineMs: OPERATION_DEADLINE_MS,
    ...overrides,
  };
  let inFlight: Promise<ProviderQuota> | undefined;

  return {
    id: "muse",
    label: LABEL,
    // One key-endpoint request per credential per process, however many
    // callers ask: concurrent callers share the in-flight reading.
    fetchQuota(options: ProviderOptions): Promise<ProviderQuota> {
      if (inFlight) return inFlight;
      const acquisition = acquireMuseQuota(dependencies, options).finally(
        () => {
          if (inFlight === acquisition) inFlight = undefined;
        },
      );
      inFlight = acquisition;
      return acquisition;
    },
    inspectAuth(options: ProviderOptions): Promise<AuthProviderReport> {
      return inspectAuth(dependencies, options);
    },
  };
}

export const museAdapter = createMuseAdapter();

/** Local only: `auth` never contacts the key endpoint, so it never issues a key. */
async function inspectAuth(
  dependencies: MuseDependencies,
  options: ProviderOptions,
): Promise<AuthProviderReport> {
  const sources: AuthSourceReport[] = [];
  for (const source of dependencies.sources) {
    const resolution = await resolveSource(
      source,
      options,
      !options.allowKeychainPrompt,
    );
    const path = safeLocation(source);
    sources.push({
      source: source.name,
      ...(path ? { path } : {}),
      ...(resolution.status === "resolved"
        ? { status: "available" as const }
        : resolution.status === "absent"
          ? { status: "missing" as const }
          : resolution.status === "skipped"
            ? {
                status: "skipped" as const,
                error: resolution.error,
                credentialPresent: true,
              }
            : resolution.status === "read_error"
              ? {
                  status: "error" as const,
                  error: resolution.error,
                  credentialPresent: true,
                }
              : {
                  status: "invalid" as const,
                  error: resolution.error,
                  credentialPresent: true,
                }),
    });
  }
  return { provider: "muse", sources };
}

async function acquireMuseQuota(
  dependencies: MuseDependencies,
  options: Pick<ProviderOptions, "allowKeychainPrompt">,
): Promise<ProviderQuota> {
  clearMuseReadingContextId();
  const localAttempts = new Map<string, SourceAttempt>();
  const candidates: CredentialCandidate<MuseCandidate>[] = [];
  let localError: string | undefined;
  let skippedCredentialError: string | undefined;

  for (const source of dependencies.sources) {
    const resolution = await resolveSource(source, options);
    if (resolution.status === "resolved") {
      candidates.push({
        source: source.name,
        localState: "valid",
        refreshable: resolution.refreshable,
        credential: {
          credential: resolution.credential,
          contextId: museCacheContextId(source.name, resolution.credential),
          ...(resolution.pingKey ? { pingKey: resolution.pingKey } : {}),
        },
      });
      continue;
    }
    if (resolution.status === "absent") {
      localAttempts.set(source.name, {
        source: source.name,
        status: "skipped",
      });
      continue;
    }
    if (resolution.status === "skipped") {
      // A present credential quota-axi may not read (a Keychain prompt the
      // caller has not granted) is not a broken store and never a sign-out.
      skippedCredentialError ??= resolution.error;
      localAttempts.set(source.name, {
        source: source.name,
        status: "skipped",
        error: resolution.error,
        credentialPresent: true,
      });
      continue;
    }
    localError ??= resolution.error;
    localAttempts.set(source.name, {
      source: source.name,
      status: "failed",
      error: resolution.error,
      credentialPresent: true,
    });
  }

  const failures = new Map<string, MuseFailure>();
  const contexts = new Map<string, string>();
  const selection = await selectCredential<MuseCandidate, MuseReading>(
    candidates,
    async (candidate) => {
      contexts.set(candidate.source, candidate.credential.contextId);
      const outcome = await attemptCandidate(candidate, dependencies);
      if (outcome.failure) failures.set(candidate.source, outcome.failure);
      return outcome.outcome;
    },
  );
  const attempts = orderedAttempts(
    dependencies.sources,
    localAttempts,
    selection.results,
  );
  const sourcesTried = attempts.map(({ source }) => source);

  if (selection.outcome === "quota" && selection.winner && selection.result) {
    const contextId = contexts.get(selection.winner.source);
    if (contextId) publishMuseReadingContextId(contextId);
    return selection.result.kind === "reused"
      ? reusedReport(selection.result.snapshot, attempts, sourcesTried)
      : freshReport(selection.result, attempts, sourcesTried);
  }

  if (selection.outcome === "transient") {
    const transient = selection.results.find(
      ({ outcome }) => outcome === "transient",
    );
    const failure =
      (transient && failures.get(transient.source)) ??
      new MuseFailure(selection.transientError ?? "provider_unavailable", {
        staleEligible: true,
      });
    const contextId = transient && contexts.get(transient.source);
    if (contextId) publishMuseReadingContextId(contextId);
    return failureReport(failure, contextId, attempts, dependencies);
  }

  if (skippedCredentialError) {
    // A present credential that may not be read without a granted prompt says
    // nothing about sign-in state; report the blocked read, never a sign-out.
    return failureReport(
      new MuseFailure(skippedCredentialError, { staleEligible: true }),
      undefined,
      attempts,
      dependencies,
    );
  }

  if (selection.outcome === "all_rejected") {
    const failure = selection.refreshable
      ? new MuseFailure("muse_access_token_rejected", {
          status: "unavailable",
          staleEligible: true,
        })
      : new MuseFailure("muse_access_token_rejected", {
          status: "auth_required",
          definitiveAuth: true,
        });
    if (!selection.refreshable) retireRejectedCache(contexts, dependencies);
    const rejected = selection.results.find(
      (result) => result.outcome === "rejected",
    );
    return failureReport(
      failure,
      rejected ? contexts.get(rejected.source) : undefined,
      attempts,
      dependencies,
      {
        authStatus: selection.refreshable ? "expired_refreshable" : "unusable",
      },
    );
  }

  if (localError) {
    // A present store that could not be read or parsed is not sign-out: the
    // user may still be signed in, and the file error is the report.
    return failureReport(
      new MuseFailure(localError),
      undefined,
      attempts,
      dependencies,
    );
  }
  return failureReport(
    new MuseFailure("muse_credential_unavailable", {
      status: "auth_required",
      definitiveAuth: true,
    }),
    undefined,
    attempts,
    dependencies,
  );
}

/**
 * One candidate's turn. The ledger decides first: inside the interval nothing
 * is sent and the last request's outcome is replayed. Otherwise the request is
 * claimed as pending in the same locked step that checked the interval, so two
 * processes cannot both POST, and a crash or timeout mid-request still counts.
 * A claim that cannot be recorded does not send.
 */
async function attemptCandidate(
  candidate: CredentialCandidate<MuseCandidate>,
  dependencies: MuseDependencies,
): Promise<{ outcome: AttemptOutcome<MuseReading>; failure?: MuseFailure }> {
  const { credential, contextId } = candidate.credential;
  const startedAt = dependencies.now();
  const claimed = claimRead(dependencies.ledger, contextId, startedAt);
  if (claimed.kind === "recent")
    return replay(claimed.read, contextId, dependencies);
  if (claimed.kind === "unwritable") {
    const failure = new MuseFailure("muse_read_unrecorded", {
      staleEligible: true,
    });
    return {
      outcome: { kind: "transient", error: failure.code },
      failure,
    };
  }
  try {
    const payload = await requestKeyUsage(credential, dependencies);
    const refreshedAt = dependencies.now();
    const normalized = normalizeMusePayload(payload, refreshedAt);

    // Fallback: the free key read omits `subs_usage` while the five-hour
    // window is idle. When the subscription is active but no usable window
    // came back, and the store carries a minted inference key, one billed
    // `/v1/responses` ping reads the windows from its `subscription_usage`
    // event. The gate claim above already bounds this to one attempt per
    // credential per interval, so a success is cached and an empty result or a
    // failure is recorded and replayed - never retried in a loop.
    if (
      shouldPingForUsage(payload, normalized) &&
      candidate.credential.pingKey !== undefined
    ) {
      const pinged = await pingForUsage(
        candidate.credential.pingKey,
        normalized,
        dependencies,
      );
      const pingedAt = dependencies.now();
      const emptyQuota = emptyQuotaMarker(pinged.payload, pingedAt, true);
      safeRecord(dependencies.ledger, contextId, {
        attemptedAt: startedAt,
        outcome: "quota",
        ...(emptyQuota ? { emptyQuota } : {}),
      });
      return {
        outcome: {
          kind: "quota",
          result: {
            kind: "fresh",
            payload: pinged.payload,
            refreshedAt: pingedAt,
            ping: pinged.windowed ? "success" : "failed",
          },
        },
      };
    }

    const emptyQuota = emptyQuotaMarker(normalized, refreshedAt);
    safeRecord(dependencies.ledger, contextId, {
      attemptedAt: startedAt,
      outcome: "quota",
      ...(emptyQuota ? { emptyQuota } : {}),
    });
    return {
      outcome: {
        kind: "quota",
        result: {
          kind: "fresh",
          payload: normalized,
          refreshedAt,
        },
      },
    };
  } catch (error) {
    const failure = asMuseFailure(error);
    safeRecord(dependencies.ledger, contextId, {
      attemptedAt: startedAt,
      outcome: failure.definitiveAuth ? "rejected" : "transient",
    });
    return failure.definitiveAuth
      ? { outcome: { kind: "rejected", error: failure.code }, failure }
      : {
          outcome: {
            kind: "transient",
            error: failure.code,
            ...(failure.retryAfter ? { retryAfter: failure.retryAfter } : {}),
          },
          failure,
        };
  }
}

/**
 * Replays the last request for this credential without sending another. A
 * windowed reading that request produced is served from its own
 * context-matched snapshot; an empty successful observation is served from
 * the ledger marker; a rejection stays a rejection; anything else is a
 * deferred read whose `retryAfter` names when the next request may leave.
 */
function replay(
  recent: MuseKeyRead,
  contextId: string,
  dependencies: MuseDependencies,
): { outcome: AttemptOutcome<MuseReading>; failure?: MuseFailure } {
  if (recent.outcome === "rejected") {
    return {
      outcome: { kind: "rejected", error: "muse_access_token_rejected" },
      failure: new MuseFailure("muse_access_token_rejected", {
        status: "auth_required",
        definitiveAuth: true,
      }),
    };
  }
  if (recent.outcome === "quota") {
    const snapshot = safeReadCache(dependencies, contextId);
    if (snapshot && reusableSnapshot(snapshot, recent, dependencies.now())) {
      return {
        outcome: { kind: "quota", result: { kind: "reused", snapshot } },
      };
    }
    if (recent.emptyQuota) {
      return {
        outcome: {
          kind: "quota",
          result: replayedEmptyQuota(recent.emptyQuota),
        },
      };
    }
  }
  const retryAfter = new Date(
    recent.attemptedAt + MUSE_KEY_READ_INTERVAL_MS,
  ).toISOString();
  // Deliberately not read, rather than a failed read: `unavailable`, not `error`.
  const failure = new MuseFailure("muse_read_deferred", {
    status: "unavailable",
    staleEligible: true,
    retryAfter,
  });
  return {
    outcome: { kind: "transient", error: failure.code, retryAfter },
    failure,
  };
}

function emptyQuotaMarker(
  payload: NormalizedMusePayload,
  refreshedAt: number,
  pinged = false,
): MuseEmptyQuota | undefined {
  if (payload.windows.length > 0) return undefined;
  return {
    refreshedAt,
    ...(payload.plan ? { plan: payload.plan } : {}),
    ...(payload.untrustedWindowIds.length > 0
      ? { untrustedWindowIds: payload.untrustedWindowIds }
      : {}),
    ...(pinged ? { pinged: true } : {}),
  };
}

function replayedEmptyQuota(emptyQuota: MuseEmptyQuota): MuseReading {
  // When the original reading fired the billed ping, keep disclosing it on the
  // replay. Only the source marker is carried on the snapshot; `reusedReport`
  // rebuilds the (failed, since there is no window) ping attempt from it.
  const pingSources = emptyQuota.pinged ? [MUSE_USAGE_PING_SOURCE] : [];
  return {
    kind: "reused",
    snapshot: {
      provider: "muse",
      label: LABEL,
      source: "api",
      ...(emptyQuota.plan ? { plan: emptyQuota.plan } : {}),
      windows: [],
      state: {
        status: "fresh",
        stale: false,
        authStatus: "usable",
        refreshedAt: new Date(emptyQuota.refreshedAt).toISOString(),
        ...(emptyQuota.untrustedWindowIds &&
        emptyQuota.untrustedWindowIds.length > 0
          ? { untrustedWindowIds: [...emptyQuota.untrustedWindowIds] }
          : {}),
        sourcesTried: pingSources,
      },
      attempts: [],
    },
  };
}

/**
 * A snapshot the replayed request itself produced (refreshed no earlier than
 * the request left), from the key endpoint, with every window's own reset
 * still ahead. A reset that passed inside the interval means the numbers
 * describe a finished window, so the reading is deferred instead. An empty
 * success is not reusable here: it replays from the ledger marker, and a
 * windowed quota cache miss must not become an empty reading.
 */
function reusableSnapshot(
  snapshot: ProviderQuota,
  recent: MuseKeyRead,
  now: number,
): boolean {
  if (
    snapshot.provider !== "muse" ||
    snapshot.source !== "api" ||
    snapshot.state.status !== "fresh" ||
    !snapshot.state.refreshedAt ||
    snapshot.windows.length === 0
  )
    return false;
  const refreshedAt = Date.parse(snapshot.state.refreshedAt);
  if (!Number.isFinite(refreshedAt) || refreshedAt < recent.attemptedAt)
    return false;
  return snapshot.windows.every((window) => {
    if (!window.resetsAt) return true;
    const resetsAt = Date.parse(window.resetsAt);
    return Number.isFinite(resetsAt) && resetsAt > now;
  });
}

function orderedAttempts(
  sources: readonly MuseCredentialSource[],
  localAttempts: Map<string, SourceAttempt>,
  results: CandidateResult[],
): SourceAttempt[] {
  const bySource = new Map(results.map((result) => [result.source, result]));
  const attempts: SourceAttempt[] = [];
  for (const source of sources) {
    const local = localAttempts.get(source.name);
    if (local) {
      attempts.push(local);
      continue;
    }
    const result = bySource.get(source.name);
    if (!result) continue;
    if (result.outcome === "quota") {
      attempts.push({ source: source.name, status: "success" });
    } else if (result.outcome === "not_tried") {
      attempts.push({
        source: source.name,
        status: "skipped",
        credentialPresent: true,
        degraded: false,
      });
    } else {
      attempts.push({
        source: source.name,
        status: "failed",
        ...(result.error ? { error: result.error } : {}),
      });
    }
  }
  return attempts;
}

function freshReport(
  reading: Extract<MuseReading, { kind: "fresh" }>,
  attempts: SourceAttempt[],
  sourcesTried: string[],
): ProviderQuota {
  const { payload } = reading;
  // When the billed usage ping ran, make it visible in `--full`: a ping
  // attempt (success or failed) and the ping source in `sourcesTried`.
  const reportedAttempts = reading.ping
    ? [
        ...attempts,
        reading.ping === "success"
          ? { source: MUSE_USAGE_PING_SOURCE, status: "success" as const }
          : {
              source: MUSE_USAGE_PING_SOURCE,
              status: "failed" as const,
              error: "muse_usage_ping_failed",
            },
      ]
    : attempts;
  const reportedSources = reading.ping
    ? [...sourcesTried, MUSE_USAGE_PING_SOURCE]
    : sourcesTried;
  return {
    provider: "muse",
    label: LABEL,
    source: "api",
    ...(payload.plan ? { plan: payload.plan } : {}),
    windows: payload.windows,
    state: {
      status: "fresh",
      stale: false,
      authStatus: "usable",
      refreshedAt: new Date(reading.refreshedAt).toISOString(),
      ...(payload.untrustedWindowIds.length > 0
        ? { untrustedWindowIds: payload.untrustedWindowIds }
        : {}),
      sourcesTried: reportedSources,
    },
    attempts: reportedAttempts,
  };
}

/**
 * The reading the last request in this interval produced, served without a new
 * request. It is still that request's fresh observation - `refreshedAt` keeps
 * its original instant and `source` says it came from the cache - so it keeps
 * its `quota[]` row instead of reading as a failed fetch.
 */
function reusedReport(
  snapshot: ProviderQuota,
  attempts: SourceAttempt[],
  sourcesTried: string[],
): ProviderQuota {
  // If the cached reading came from the billed ping, keep disclosing it: carry
  // the ping attempt and source forward so the replay still shows the metered
  // fallback in `--full` rather than hiding it behind the cache row. The cache
  // persists `sourcesTried` but not `attempts`, so the source list is the
  // durable signal that the ping produced this reading.
  const snapshotPinged =
    snapshot.state.sourcesTried?.includes(MUSE_USAGE_PING_SOURCE) === true;
  // A pinged snapshot with windows is a ping success; a pinged snapshot with no
  // window is the empty/failed ping replayed from its ledger marker.
  const pingAttempt =
    snapshot.windows.length > 0
      ? { source: MUSE_USAGE_PING_SOURCE, status: "success" as const }
      : {
          source: MUSE_USAGE_PING_SOURCE,
          status: "failed" as const,
          error: "muse_usage_ping_failed",
        };
  const reportedAttempts = snapshotPinged
    ? [...attempts, pingAttempt]
    : attempts;
  const reportedSources = snapshotPinged
    ? [...sourcesTried, MUSE_USAGE_PING_SOURCE, "cache"]
    : [...sourcesTried, "cache"];
  return {
    provider: "muse",
    label: LABEL,
    source: "cache",
    ...(snapshot.plan ? { plan: snapshot.plan } : {}),
    windows: snapshot.windows,
    state: {
      status: "fresh",
      stale: false,
      authStatus: "usable",
      ...(snapshot.state.refreshedAt
        ? { refreshedAt: snapshot.state.refreshedAt }
        : {}),
      ...(snapshot.state.untrustedWindowIds
        ? { untrustedWindowIds: snapshot.state.untrustedWindowIds }
        : {}),
      sourcesTried: reportedSources,
    },
    attempts: reportedAttempts,
  };
}

function failureReport(
  failure: MuseFailure,
  contextId: string | undefined,
  attempts: SourceAttempt[],
  dependencies: MuseDependencies,
  overrides: { authStatus?: "expired_refreshable" | "unusable" } = {},
): ProviderQuota {
  const sourcesTried = attempts.map(({ source }) => source);
  const authStatus: ProviderAuthStatus | undefined =
    overrides.authStatus ??
    (failure.authUsable
      ? "usable"
      : failure.definitiveAuth
        ? "unusable"
        : undefined);
  if (failure.staleEligible && contextId) {
    const cached = safeReadCache(dependencies, contextId);
    const stale = cached
      ? staleMuseReport(
          cached,
          failure,
          attempts,
          dependencies.now(),
          authStatus,
        )
      : undefined;
    if (stale) return stale;
  }

  return {
    provider: "muse",
    label: LABEL,
    source: "unavailable",
    windows: [],
    state: {
      status: failure.status,
      stale: false,
      error: failure.code,
      ...(authStatus ? { authStatus } : {}),
      ...(failure.retryAfter ? { retryAfter: failure.retryAfter } : {}),
      sourcesTried,
    },
    attempts,
  };
}

function staleMuseReport(
  cached: ProviderQuota,
  failure: MuseFailure,
  attempts: SourceAttempt[],
  now: number,
  authStatus: ProviderAuthStatus | undefined,
): ProviderQuota | undefined {
  if (
    cached.provider !== "muse" ||
    cached.source !== "api" ||
    cached.state.status !== "fresh" ||
    !cached.state.refreshedAt
  )
    return undefined;
  const refreshedAt = Date.parse(cached.state.refreshedAt);
  if (!Number.isFinite(refreshedAt)) return undefined;
  const windows = servableStaleWindows(cached, now);
  if (windows.length === 0) return undefined;
  const untrustedWindowIds = servableUntrustedWindowIds(cached, windows);

  return {
    provider: "muse",
    label: LABEL,
    source: "cache",
    ...(cached.plan ? { plan: cached.plan } : {}),
    windows,
    state: {
      status: "stale",
      stale: true,
      refreshedAt: cached.state.refreshedAt,
      error: failure.code,
      ...(authStatus ? { authStatus } : {}),
      ...(failure.retryAfter ? { retryAfter: failure.retryAfter } : {}),
      ...(untrustedWindowIds ? { untrustedWindowIds } : {}),
      sourcesTried: [...attempts.map(({ source }) => source), "cache"],
    },
    attempts,
  };
}

function retireRejectedCache(
  contexts: Map<string, string>,
  dependencies: MuseDependencies,
): void {
  try {
    for (const contextId of contexts.values()) {
      if (dependencies.readCachedProvider(contextId)) {
        dependencies.deleteCachedProvider();
        return;
      }
    }
  } catch {
    // The current auth failure is still definitive even if the cache is not writable.
  }
}

/**
 * The one request: the call the Muse CLI makes at startup, `POST
 * /muse-code/key` with `{"onboard": false}` and `x-api-version: 1.0.0`. The
 * response carries the account's Model API key alongside the subscription
 * usage; only the usage keys survive parsing, and no response body ever
 * reaches an error or a log.
 */
async function requestKeyUsage(
  credential: string,
  dependencies: MuseDependencies,
): Promise<unknown> {
  const controller = new AbortController();
  const signal = controller.signal;
  const timeout = new Promise<never>((_resolve, reject) => {
    signal.addEventListener(
      "abort",
      () => reject(new MuseFailure("request_timeout", { staleEligible: true })),
      { once: true },
    );
  });
  timeout.catch(() => undefined);
  const deadline = setTimeout(
    () => controller.abort(),
    dependencies.deadlineMs,
  );
  try {
    return await Promise.race([
      sendKeyUsageRequest(credential, signal, dependencies),
      timeout,
    ]);
  } finally {
    clearTimeout(deadline);
  }
}

async function sendKeyUsageRequest(
  credential: string,
  signal: AbortSignal,
  dependencies: MuseDependencies,
): Promise<unknown> {
  const url = new URL(MUSE_KEY_PATH, MUSE_API_ORIGIN).href;
  let response: Response;
  try {
    response = await dependencies.fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": USER_AGENT,
        "x-api-version": MUSE_API_VERSION,
      },
      body: JSON.stringify({ onboard: false }),
      credentials: "omit",
      redirect: "manual",
      signal,
    });
  } catch (error) {
    if (signal.aborted || isAbortError(error))
      throw new MuseFailure("request_timeout", { staleEligible: true });
    throw new MuseFailure(localTransportCode(error), { staleEligible: true });
  }

  if (response.status !== 200) {
    await response.body?.cancel().catch(() => undefined);
    rejectHttpFailure(response, dependencies.now());
  }

  let bytes: Uint8Array;
  try {
    bytes = await readBoundedResponseBody(
      response,
      signal,
      (code) => new MuseFailure(code, { staleEligible: true }),
    );
  } catch (error) {
    if (error instanceof MuseFailure) throw error;
    if (signal.aborted || isAbortError(error))
      throw new MuseFailure("request_timeout", { staleEligible: true });
    throw new MuseFailure("network_unavailable", { staleEligible: true });
  }
  try {
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      (key, value: unknown) =>
        key === "" || RESPONSE_KEYS.has(key) ? value : undefined,
    ) as unknown;
  } catch {
    throw new MuseFailure("malformed_json", { staleEligible: true });
  }
}

function rejectHttpFailure(response: Response, receivedAt: number): never {
  const status = response.status;
  if (status >= 300 && status <= 399)
    throw new MuseFailure("redirect_rejected", { staleEligible: true });
  if (status === 401)
    throw new MuseFailure("muse_access_token_rejected", {
      status: "auth_required",
      definitiveAuth: true,
    });
  // 403 is not sign-out evidence: network policy and WAF denials use it too.
  if (status === 403)
    throw new MuseFailure("provider_request_forbidden", {
      staleEligible: true,
    });
  if (status === 408)
    throw new MuseFailure("provider_timeout", {
      authUsable: true,
      staleEligible: true,
    });
  if (status === 429)
    throw new MuseFailure("provider_rate_limited", {
      status: "rate_limited",
      authUsable: true,
      staleEligible: true,
      retryAfter: retryAfterToIso(
        response.headers.get("retry-after"),
        receivedAt,
      ),
    });
  if (status >= 500 && status <= 599)
    throw new MuseFailure("provider_unavailable", {
      authUsable: true,
      staleEligible: true,
    });
  throw new MuseFailure("provider_request_rejected", {
    authUsable: true,
    staleEligible: true,
  });
}

/**
 * Whether to fall back to the billed usage ping. Only when the free key read
 * succeeded for an active subscription (`is_subs_active` is not `false`) yet
 * published no window and named none as untrusted - the documented idle
 * five-hour case where Meta omits `subs_usage` entirely. A present-but-garbled
 * usage object (named in `untrustedWindowIds`) is a different signal and is
 * reported as-is rather than spending a request on it.
 */
function shouldPingForUsage(
  payload: unknown,
  normalized: NormalizedMusePayload,
): boolean {
  const root = objectValue(payload);
  if (!root || root.is_subs_active === false) return false;
  return (
    normalized.windows.length === 0 &&
    normalized.untrustedWindowIds.length === 0
  );
}

/**
 * The billed fallback. One `/v1/responses` request with the smallest output the
 * API allows reads the subscription windows from the stream's
 * `response.subscription_usage` event. A failure here is not fatal: the free
 * read already succeeded, so the empty reading it produced is returned
 * unchanged (and recorded, so the gate does not retry the ping this interval).
 */
async function pingForUsage(
  pingKey: string,
  fallback: NormalizedMusePayload,
  dependencies: MuseDependencies,
): Promise<{ payload: NormalizedMusePayload; windowed: boolean }> {
  try {
    const subscription = await requestSubscriptionUsagePing(
      pingKey,
      dependencies,
    );
    const windows = normalizeMuseSubscription(subscription, dependencies.now());
    // A ping that returned no usable window keeps the free read's result,
    // including its plan, rather than discarding it for an empty ping.
    if (windows.windows.length === 0)
      return { payload: fallback, windowed: false };
    return {
      payload: {
        ...(fallback.plan ? { plan: fallback.plan } : {}),
        windows: windows.windows,
        untrustedWindowIds: windows.untrustedWindowIds,
      },
      windowed: true,
    };
  } catch {
    return { payload: fallback, windowed: false };
  }
}

/**
 * The one billed request. `POST /v1/responses`, bearer = the minted inference
 * key, smallest allowed output, streamed. Reads the stream only until the
 * `response.subscription_usage` event, then stops. No model text, token count,
 * or account field is retained.
 */
async function requestSubscriptionUsagePing(
  pingKey: string,
  dependencies: MuseDependencies,
): Promise<unknown> {
  const controller = new AbortController();
  const signal = controller.signal;
  const deadline = setTimeout(
    () => controller.abort(),
    dependencies.deadlineMs,
  );
  const url = new URL(MUSE_RESPONSES_PATH, MUSE_API_ORIGIN).href;
  try {
    let response: Response;
    try {
      response = await dependencies.fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${pingKey}`,
          "Content-Type": "application/json",
          Accept: "text/event-stream",
          "User-Agent": USER_AGENT,
        },
        body: JSON.stringify({
          model: MUSE_PING_MODEL,
          input: "ping",
          stream: true,
          max_output_tokens: MUSE_PING_MAX_OUTPUT_TOKENS,
        }),
        credentials: "omit",
        redirect: "manual",
        signal,
      });
    } catch (error) {
      if (signal.aborted || isAbortError(error))
        throw new MuseFailure("request_timeout", { staleEligible: true });
      throw new MuseFailure(localTransportCode(error), { staleEligible: true });
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      rejectHttpFailure(response, dependencies.now());
    }
    return await readSubscriptionUsageStream(response.body, signal);
  } finally {
    clearTimeout(deadline);
  }
}

/**
 * Reads an SSE stream only as far as the first `response.subscription_usage`
 * event, bounded by `readBoundedResponseBody`'s size limit via the shared
 * reader. Returns the parsed `subscription` object, or throws when the stream
 * ends without one.
 */
async function readSubscriptionUsageStream(
  body: ReadableStream<Uint8Array> | null,
  signal: AbortSignal,
): Promise<unknown> {
  if (!body)
    throw new MuseFailure("muse_stream_missing", { staleEligible: true });
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  let event: string | undefined;
  const dataLines: string[] = [];
  let received = 0;
  const limit = 256 * 1024;
  try {
    for (;;) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch (error) {
        if (signal.aborted || isAbortError(error))
          throw new MuseFailure("request_timeout", { staleEligible: true });
        throw new MuseFailure("network_unavailable", { staleEligible: true });
      }
      if (chunk.done) break;
      received += chunk.value.byteLength;
      if (received > limit)
        throw new MuseFailure("response_too_large", { staleEligible: true });
      try {
        buffer += decoder.decode(chunk.value, { stream: true });
      } catch {
        throw new MuseFailure("response_invalid_utf8", { staleEligible: true });
      }
      const lines = buffer.split(/\r?\n/u);
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (line === "") {
          const subscription = subscriptionFromEvent(event, dataLines);
          event = undefined;
          dataLines.length = 0;
          if (subscription !== undefined) return subscription;
        } else if (line.startsWith("event:")) {
          event = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).replace(/^ /u, ""));
        }
      }
    }
    const subscription = subscriptionFromEvent(event, dataLines);
    if (subscription !== undefined) return subscription;
    throw new MuseFailure("muse_subscription_missing", { staleEligible: true });
  } finally {
    try {
      await reader.cancel();
    } catch {
      // Cancelling a finished or failed stream does not change the result.
    }
    reader.releaseLock();
  }
}

/**
 * Parses one completed SSE event. Returns the `subscription` object only for a
 * `response.subscription_usage` event; every other event yields `undefined`.
 * The body is parsed through a key-allowlist reviver, so no model text or
 * token count survives.
 */
function subscriptionFromEvent(
  event: string | undefined,
  dataLines: string[],
): unknown {
  if (event !== MUSE_SUBSCRIPTION_USAGE_EVENT || dataLines.length === 0)
    return undefined;
  const text = dataLines.join("\n").trim();
  if (!text || text === "[DONE]") return undefined;
  let payload: unknown;
  try {
    payload = JSON.parse(text, (key, value: unknown) =>
      key === "" || RESPONSES_EVENT_KEYS.has(key) ? value : undefined,
    );
  } catch {
    return undefined;
  }
  const subscription = objectValue(objectValue(payload)?.subscription);
  return subscription ?? undefined;
}

/**
 * The `response.subscription_usage` event mirrors `subs_usage`: a `window`
 * (rolling, 300 minutes on observed plans) and a `weekly` entry, each with
 * `used_percent` and `resets_at`. Reuses the same window-building rules as the
 * key endpoint so a ping-sourced reading is indistinguishable in shape.
 */
function normalizeMuseSubscription(
  subscription: unknown,
  now: number,
): NormalizedMusePayload {
  const root = objectValue(subscription);
  const result: NormalizedMusePayload = { windows: [], untrustedWindowIds: [] };
  if (!root) return result;
  if (Object.hasOwn(root, "window")) {
    const entry = objectValue(root.window);
    const minutes = positiveFinite(entry?.window_duration_mins);
    const windowSeconds =
      minutes === undefined ? undefined : Math.round(minutes * 60);
    const fiveHour = minutes === FIVE_HOUR_MINUTES;
    pushWindow(
      result,
      "subs_usage:window",
      entry,
      {
        id: fiveHour ? "five_hour" : "window",
        label: fiveHour
          ? "session"
          : windowSeconds === undefined
            ? "window"
            : `${readableHours(windowSeconds)} window`,
        kind: fiveHour ? "session" : "unknown",
        ...(fiveHour
          ? { windowSeconds: FIVE_HOURS_SECONDS }
          : windowSeconds === undefined
            ? {}
            : { windowSeconds }),
      },
      now,
    );
  }
  if (Object.hasOwn(root, "weekly")) {
    pushWindow(
      result,
      "subs_usage:weekly",
      objectValue(root.weekly),
      {
        id: "weekly",
        label: "week",
        kind: "weekly",
        windowSeconds: WEEK_SECONDS,
      },
      now,
    );
  }
  return result;
}

/**
 * The subscription's `window` (the rolling window, 300 minutes on the plans
 * observed) and `weekly` usage. Absent entries stay absent, including an
 * omitted or null `subs_usage` on an otherwise valid body. An entry that is
 * present but carries no usable `used_percent` is named in
 * `untrustedWindowIds` instead of guessed at, and a reset the vendor reports as
 * already passed publishes no live window and is named there so the remaining
 * window cannot stand in as a definitive bound. An inactive subscription
 * reports no window at all.
 */
export function normalizeMusePayload(
  payload: unknown,
  now: number,
): NormalizedMusePayload {
  const root = objectValue(payload);
  if (
    !root ||
    (!Object.hasOwn(root, "is_subs_active") &&
      !Object.hasOwn(root, "subs_usage"))
  )
    throw new MuseFailure("schema_invalid", { staleEligible: true });

  const plan = nonemptyString(root.subs_tier_name);
  const result: NormalizedMusePayload = {
    ...(plan ? { plan } : {}),
    windows: [],
    untrustedWindowIds: [],
  };
  if (root.is_subs_active === false) return result;

  const usage = objectValue(root.subs_usage);
  if (!usage) {
    // Omitted or null means the vendor supplied no windows. A present
    // non-object is untrusted because it cannot be read as usage.
    if (root.subs_usage != null) result.untrustedWindowIds.push("subs_usage");
    return result;
  }

  // A present usage object that names neither recognized window is an
  // unrecognized shape, not the established omitted/null empty reading: mark
  // it untrusted so it is not mistaken for "no usage" and does not trigger the
  // billed usage ping.
  if (!Object.hasOwn(usage, "window") && !Object.hasOwn(usage, "weekly")) {
    result.untrustedWindowIds.push("subs_usage");
    return result;
  }

  if (Object.hasOwn(usage, "window")) {
    const entry = objectValue(usage.window);
    const minutes = positiveFinite(entry?.window_duration_mins);
    const windowSeconds =
      minutes === undefined ? undefined : Math.round(minutes * 60);
    const fiveHour = minutes === FIVE_HOUR_MINUTES;
    pushWindow(
      result,
      "subs_usage:window",
      entry,
      {
        id: fiveHour ? "five_hour" : "window",
        label: fiveHour
          ? "session"
          : windowSeconds === undefined
            ? "window"
            : `${readableHours(windowSeconds)} window`,
        kind: fiveHour ? "session" : "unknown",
        ...(fiveHour
          ? { windowSeconds: FIVE_HOURS_SECONDS }
          : windowSeconds === undefined
            ? {}
            : { windowSeconds }),
      },
      now,
    );
  }
  if (Object.hasOwn(usage, "weekly")) {
    pushWindow(
      result,
      "subs_usage:weekly",
      objectValue(usage.weekly),
      {
        id: "weekly",
        label: "week",
        kind: "weekly",
        windowSeconds: WEEK_SECONDS,
      },
      now,
    );
  }
  return result;
}

function pushWindow(
  result: NormalizedMusePayload,
  untrustedId: string,
  entry: Record<string, unknown> | undefined,
  identity: Pick<QuotaWindow, "id" | "label" | "kind" | "windowSeconds">,
  now: number,
): void {
  const used =
    typeof entry?.used_percent === "number" &&
    Number.isFinite(entry.used_percent) &&
    entry.used_percent >= 0
      ? entry.used_percent
      : undefined;
  if (used === undefined) {
    result.untrustedWindowIds.push(untrustedId);
    return;
  }
  const resetsAt = parseResetSeconds(entry?.resets_at);
  if (resetsAt !== undefined && Date.parse(resetsAt) <= now) {
    result.untrustedWindowIds.push(identity.id);
    return;
  }
  const percentUsed = Math.min(100, Number(used.toFixed(10)));
  result.windows.push({
    ...identity,
    percentUsed,
    percentRemaining: Number((100 - percentUsed).toFixed(10)),
    ...(resetsAt ? { resetsAt } : {}),
  });
}

/** Epoch seconds only; anything else leaves the reset unresolved. */
function parseResetSeconds(value: unknown): string | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  if (value < 1_000_000_000 || value >= 100_000_000_000) return undefined;
  return new Date(value * 1000).toISOString();
}

function readableHours(windowSeconds: number): string {
  const hours = windowSeconds / 3600;
  return `${Number.isInteger(hours) ? hours : Number(hours.toFixed(2))}h`;
}

async function resolveSource(
  source: MuseCredentialSource,
  options: Pick<ProviderOptions, "allowKeychainPrompt">,
  presenceOnly = false,
): Promise<MuseLocalResolution> {
  try {
    return await source.resolve(options, presenceOnly);
  } catch {
    return { status: "read_error", error: "credential_resolution_failed" };
  }
}

function safeLocation(source: MuseCredentialSource): string | undefined {
  try {
    return source.location();
  } catch {
    return undefined;
  }
}

function claimRead(
  ledger: MuseKeyReadLedger,
  contextId: string,
  now: number,
): MuseKeyReadClaim {
  try {
    return ledger.claim(contextId, now);
  } catch {
    return { kind: "unwritable" };
  }
}

/**
 * Best effort for the outcome after a recorded claim. The pending entry still
 * gates the interval if this write cannot land.
 */
function safeRecord(
  ledger: MuseKeyReadLedger,
  contextId: string,
  read: MuseKeyRead,
): void {
  try {
    ledger.record(contextId, read);
  } catch {
    // See above.
  }
}

function safeReadCache(
  dependencies: MuseDependencies,
  contextId: string,
): ProviderQuota | undefined {
  try {
    return dependencies.readCachedProvider(contextId);
  } catch {
    return undefined;
  }
}

function asMuseFailure(error: unknown): MuseFailure {
  return error instanceof MuseFailure
    ? error
    : new MuseFailure("provider_unavailable", { staleEligible: true });
}

function localTransportCode(
  error: unknown,
): "tls_failed" | "network_unavailable" {
  const cause = objectValue(objectValue(error)?.cause);
  const code = typeof cause?.code === "string" ? cause.code : undefined;
  return code && /(?:TLS|SSL|CERT|UNABLE_TO_VERIFY)/i.test(code)
    ? "tls_failed"
    : "network_unavailable";
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function errorCode(error: unknown): string | undefined {
  const code = objectValue(error)?.code;
  return typeof code === "string" ? code : undefined;
}

function positiveFinite(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? value
    : undefined;
}

function nonemptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

class MuseFailure extends Error {
  readonly code: string;
  readonly status: ProviderStatus;
  readonly staleEligible: boolean;
  readonly definitiveAuth: boolean;
  readonly authUsable: boolean;
  readonly retryAfter?: string;

  constructor(code: string, options: MuseFailureOptions = {}) {
    super(code);
    this.name = "MuseFailure";
    this.code = code;
    this.status = options.status ?? "error";
    this.staleEligible = options.staleEligible === true;
    this.definitiveAuth = options.definitiveAuth === true;
    this.authUsable = options.authUsable === true;
    this.retryAfter = options.retryAfter;
  }
}
