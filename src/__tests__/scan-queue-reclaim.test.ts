import { describe, it, expect } from "vitest";
import { isScanStale } from "@/lib/scan-queue";

const NOW = Date.parse("2026-06-29T09:00:00Z");
const STALE_MS = 5 * 60 * 1000; // 5 minutes

describe("isScanStale", () => {
  it("flags a running scan whose heartbeat is older than the threshold", () => {
    expect(
      isScanStale(
        { id: "1", status: "running", heartbeatAt: "2026-06-29T08:50:00Z", startedAt: "2026-06-29T08:49:00Z" },
        NOW,
        STALE_MS
      )
    ).toBe(true);
  });

  it("keeps a running scan with a fresh heartbeat", () => {
    expect(
      isScanStale({ id: "2", status: "running", heartbeatAt: "2026-06-29T08:58:00Z", startedAt: null }, NOW, STALE_MS)
    ).toBe(false);
  });

  it("ignores non-running scans even if the heartbeat is ancient", () => {
    expect(
      isScanStale({ id: "3", status: "completed", heartbeatAt: "2026-06-29T08:00:00Z", startedAt: null }, NOW, STALE_MS)
    ).toBe(false);
  });

  it("falls back to startedAt when heartbeatAt is missing", () => {
    expect(
      isScanStale({ id: "4", status: "running", heartbeatAt: null, startedAt: "2026-06-29T08:40:00Z" }, NOW, STALE_MS)
    ).toBe(true);
  });

  it("leaves a scan alone when no timestamp is available", () => {
    expect(isScanStale({ id: "5", status: "running", heartbeatAt: null, startedAt: null }, NOW, STALE_MS)).toBe(false);
  });
});
