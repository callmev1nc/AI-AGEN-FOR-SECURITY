import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Regression test for the cross-user alert delivery bug: notifyNewCriticalFindings
 * must deliver ONLY to the asset owner's channels, never to other users' channels.
 *
 * The admin-client mock emulates Supabase's thenable query builder and actually
 * honours the `.eq("userId", ...)` filter, so a correct implementation yields a
 * single delivery to the owner; a buggy one (no userId filter) yields two.
 */
vi.mock("@/lib/supabase/admin", () => {
  // Two users' channels exist in the (mocked) DB. The asset under test is owned
  // by userA, so only chA must ever receive an alert.
  const CHANNELS = [
    { id: "chA", userId: "userA", type: "slack", config: { webhookUrl: "https://hooks.slack.com/A" }, isActive: true },
    { id: "chB", userId: "userB", type: "slack", config: { webhookUrl: "https://hooks.slack.com/B" }, isActive: true },
  ];

  return {
    createAdminClient: () => {
      let currentTable = "";
      let userIdFilter: string | undefined;
      const chain: Record<string, unknown> = {};

      const resolveList = () => {
        if (currentTable === "alert_channels") {
          return CHANNELS.filter((c) => !userIdFilter || c.userId === userIdFilter);
        }
        return null;
      };
      const resolveSingle = () =>
        currentTable === "monitored_assets" ? { userId: "userA" } : null;

      chain.select = vi.fn(() => chain);
      chain.eq = vi.fn((col: string, val: unknown) => {
        if (col === "userId") userIdFilter = val as string;
        return chain;
      });
      chain.single = vi.fn(async () => ({ data: resolveSingle(), error: null }));
      chain.insert = vi.fn(async () => ({ error: null }));
      (chain as { then?: (f: (v: unknown) => unknown) => Promise<unknown> }).then = (onFulfilled) =>
        Promise.resolve({ data: resolveList(), error: null }).then(onFulfilled);

      return {
        from: vi.fn((table: string) => {
          currentTable = table;
          userIdFilter = undefined;
          return chain;
        }),
      };
    },
  };
});

import { notifyNewCriticalFindings } from "@/server/services/notify";

describe("notifyNewCriticalFindings — owner scoping", () => {
  beforeEach(() => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok", { status: 200 }));
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("delivers only to the asset owner's channels, never other users", async () => {
    await notifyNewCriticalFindings("scan1", "asset1", 2);

    const calls = (globalThis.fetch as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe("https://hooks.slack.com/A"); // owner userA — never userB
  });

  it("sends nothing when there are no new critical findings", async () => {
    await notifyNewCriticalFindings("scan1", "asset1", 0);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
