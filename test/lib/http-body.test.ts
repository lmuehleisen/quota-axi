import { describe, expect, it } from "vitest";
import {
  PROVIDER_RESPONSE_LIMIT_BYTES,
  readBoundedResponseJson,
  providerRequestFailure,
} from "../../src/lib/http.js";

const signal = () => new AbortController().signal;
describe("bounded provider JSON", () => {
  it("parses a response exactly at the decoded byte cap", async () => {
    const body = JSON.stringify({
      padding: "x".repeat(PROVIDER_RESPONSE_LIMIT_BYTES - 14),
    });
    expect(Buffer.byteLength(body)).toBe(PROVIDER_RESPONSE_LIMIT_BYTES);
    await expect(
      readBoundedResponseJson(new Response(body), signal()),
    ).resolves.toHaveProperty("padding");
  });
  it.each(["declared", "streamed", "multibyte"])(
    "rejects %s oversize",
    async (kind) => {
      const cancel = () => new Promise<void>(() => {});
      const response =
        kind === "declared"
          ? new Response(new ReadableStream({ cancel }), {
              headers: {
                "content-length": String(PROVIDER_RESPONSE_LIMIT_BYTES + 1),
              },
            })
          : new Response(
              JSON.stringify({
                padding: (kind === "multibyte" ? "é" : "x").repeat(
                  PROVIDER_RESPONSE_LIMIT_BYTES,
                ),
              }),
            );
      await expect(
        readBoundedResponseJson(response, signal()),
      ).rejects.toMatchObject({ message: "response_too_large" });
    },
  );
  it.each(["SYNTHETIC_ACCESS_CANARY", '{"email":"canary@example.com'])(
    "does not quote malformed body %s",
    async (body) => {
      await expect(
        readBoundedResponseJson(new Response(body), signal()),
      ).rejects.toMatchObject({ message: "invalid_json" });
    },
  );
  it("bounds a stalled stream even when cancellation never completes", async () => {
    const controller = new AbortController();
    const response = new Response(
      new ReadableStream({ cancel: () => new Promise(() => {}) }),
    );
    const pending = readBoundedResponseJson(response, controller.signal);
    controller.abort();
    await expect(pending).rejects.toMatchObject({
      message: "provider_timeout",
    });
  });
  it("does not echo a body-stream exception", async () => {
    const response = new Response(
      new ReadableStream({
        start(controller) {
          controller.error(
            new Error(
              "SYNTHETIC_ACCESS_CANARY canary@example.com account-canary",
            ),
          );
        },
      }),
    );
    await expect(
      readBoundedResponseJson(response, signal()),
    ).rejects.toMatchObject({ message: "provider_request_failed" });
  });
  it("does not trust arbitrary exception messages or codes", () => {
    const error = Object.assign(new Error("SYNTHETIC_ACCESS_CANARY"), {
      code: "SYNTHETIC_ACCESS_CANARY",
    });
    expect(providerRequestFailure(error).message).toBe(
      "provider_request_failed",
    );
  });
});
