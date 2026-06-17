import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { checkRateLimit } from "@/lib/rate-limit";

/**
 * Exercises the in-memory fallback path (no Upstash env). Uses fake timers so
 * the 1-hour window can be advanced to verify reset behavior.
 */
describe("checkRateLimit (in-memory fallback)", () => {
  beforeEach(() => {
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    vi.useFakeTimers();
  });
  afterEach(() => vi.useRealTimers());

  it("allows up to the plan limit then blocks the next request", async () => {
    const id = `free-${Math.random()}`;
    for (let i = 0; i < 5; i++) {
      const r = await checkRateLimit(id, "free");
      expect(r.success).toBe(true);
    }
    const blocked = await checkRateLimit(id, "free");
    expect(blocked.success).toBe(false);
    expect(blocked.limit).toBe(5);
  });

  it("respects plan limits (pro = 30)", async () => {
    const id = `pro-${Math.random()}`;
    for (let i = 0; i < 30; i++) {
      expect((await checkRateLimit(id, "pro")).success).toBe(true);
    }
    expect((await checkRateLimit(id, "pro")).success).toBe(false);
  });

  it("resets after the window elapses", async () => {
    const id = `reset-${Math.random()}`;
    for (let i = 0; i < 5; i++) await checkRateLimit(id, "free");
    expect((await checkRateLimit(id, "free")).success).toBe(false);

    // Advance past the 1-hour window.
    vi.advanceTimersByTime(60 * 60 * 1000 + 1);
    expect((await checkRateLimit(id, "free")).success).toBe(true);
  });

  it("isolates identifiers and defaults unknown plans to the free limit", async () => {
    const a = `iso-a-${Math.random()}`;
    const b = `iso-b-${Math.random()}`;
    await checkRateLimit(a, "free");
    // A different identifier is unaffected.
    expect((await checkRateLimit(b, "free")).success).toBe(true);
    // Unknown plan falls back to free (limit 5).
    const c = `unk-${Math.random()}`;
    expect((await checkRateLimit(c, "bogus-plan" as unknown as string)).limit).toBe(5);
  });
});
