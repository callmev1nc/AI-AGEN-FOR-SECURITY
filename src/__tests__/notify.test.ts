import { describe, it, expect } from "vitest";
import { deliverAlert } from "@/server/services/notify";

describe("notify", () => {
  it("returns false for unknown channel type", async () => {
    const result = await deliverAlert(
      { id: "test", assetId: "a", scanId: "s", newCriticalCount: 3, channelId: null },
      { id: "c", userId: "u", type: "pagerduty" as "email", config: {}, isActive: true }
    );
    expect(result).toBe(false);
  });

  it("returns false for webhook without url", async () => {
    const result = await deliverAlert(
      { id: "test", assetId: "a", scanId: "s", newCriticalCount: 3, channelId: null },
      { id: "c", userId: "u", type: "webhook", config: {}, isActive: true }
    );
    expect(result).toBe(false);
  });

  it("returns false for slack without webhookUrl", async () => {
    const result = await deliverAlert(
      { id: "test", assetId: "a", scanId: "s", newCriticalCount: 3, channelId: null },
      { id: "c", userId: "u", type: "slack", config: {}, isActive: true }
    );
    expect(result).toBe(false);
  });
});
