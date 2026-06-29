import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mockRunScanInline = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));

vi.mock("@/lib/scan-runner", () => ({
  runScanInline: (...args: unknown[]) => mockRunScanInline(...args),
}));

describe("scan queue", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    process.env = { ...origEnv };
    mockRunScanInline.mockClear();
  });

  it("enqueueScan falls back to inline when queue is disabled", async () => {
    process.env.SCAN_QUEUE_ENABLED = "0";
    process.env.REDIS_URL = "";

    const { enqueueScan } = await import("@/lib/scan-queue");
    await enqueueScan({ scanId: "test-id", targetUrl: "https://example.com", scanLevel: "deep" });
    expect(mockRunScanInline).toHaveBeenCalledWith({
      scanId: "test-id",
      targetUrl: "https://example.com",
      scanLevel: "deep",
    });
  });

  it("exports isEnabled as false when env not set", async () => {
    process.env.SCAN_QUEUE_ENABLED = "";
    const { isEnabled } = await import("@/lib/scan-queue");
    expect(isEnabled).toBe(false);
  });

  it("exports isEnabled as true when env is 1", async () => {
    process.env.SCAN_QUEUE_ENABLED = "1";
    const { isEnabled } = await import("@/lib/scan-queue");
    expect(isEnabled).toBe(true);
  });
});
