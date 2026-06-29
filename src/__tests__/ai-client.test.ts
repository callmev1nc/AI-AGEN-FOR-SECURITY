import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { callClaude } from "@/lib/ai/client";

function okResponse(text: string) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      content: [{ text }],
      usage: { input_tokens: 1, output_tokens: 2 },
    }),
  };
}

describe("callClaude", () => {
  const origKey = process.env.ANTHROPIC_API_KEY;

  beforeEach(() => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    vi.useFakeTimers();
  });
  afterEach(() => {
    process.env.ANTHROPIC_API_KEY = origKey;
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("returns the assistant text on success", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(okResponse("hello")));
    await expect(callClaude([{ role: "user", content: "hi" }])).resolves.toBe("hello");
  });

  it("retries on failure and succeeds on a later attempt", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 500, text: async () => "err" })
      .mockResolvedValueOnce(okResponse("recovered"));
    vi.stubGlobal("fetch", fetchMock);

    const p = callClaude([{ role: "user", content: "hi" }], { retries: 2 });
    await vi.runAllTimersAsync(); // skip exponential backoff
    await expect(p).resolves.toBe("recovered");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("throws after exhausting retries", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 500, text: async () => "boom" });
    vi.stubGlobal("fetch", fetchMock);

    const p = callClaude([{ role: "user", content: "hi" }], { retries: 1 });
    // Attach a handler synchronously so the rejection is never observed as
    // "unhandled" before expect(p).rejects runs below.
    p.catch(() => {});
    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow();
    // initial attempt + 1 retry
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not retry on non-retryable 4xx (e.g. 400)", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 400, text: async () => "bad request" });
    vi.stubGlobal("fetch", fetchMock);

    const p = callClaude([{ role: "user", content: "hi" }], { retries: 2 });
    p.catch(() => {});
    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow();
    // Must NOT retry a deterministic client error.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries on 429 (rate limit)", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 429, text: async () => "slow down" })
      .mockResolvedValueOnce(okResponse("after-cooldown"));
    vi.stubGlobal("fetch", fetchMock);

    const p = callClaude([{ role: "user", content: "hi" }], { retries: 2 });
    await vi.runAllTimersAsync();
    await expect(p).resolves.toBe("after-cooldown");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("joins multi-block content", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        okResponse("part-1")
      )
    );
    // single block still returns the text
    await expect(callClaude([{ role: "user", content: "hi" }])).resolves.toBe("part-1");
  });
});
