import { describe, it, expect, beforeEach } from "vitest";
import { vi } from "vitest";
import { createHmac } from "crypto";

// Hoisted shared state so the (hoisted) mock factories can reference it.
const { seen, handleWebhookMock, state } = vi.hoisted(() => ({
  seen: new Set<string>(),
  handleWebhookMock: vi.fn(),
  state: { queriedEventId: "" },
}));

vi.mock("@/server/services/billing", () => ({
  handleWebhook: (...a: unknown[]) => handleWebhookMock(...a),
}));

vi.mock("@/lib/supabase/admin", () => ({
  createAdminClient: () => ({
    from: () => {
      const chain: Record<string, (...a: unknown[]) => unknown> = {};
      chain.select = vi.fn(() => chain);
      chain.eq = vi.fn((col: string, val: string) => {
        if (col === "eventId") state.queriedEventId = String(val);
        return chain;
      });
      chain.maybeSingle = vi.fn(async () => ({
        data: seen.has(state.queriedEventId)
          ? { eventId: state.queriedEventId }
          : null,
      }));
      chain.upsert = vi.fn(async (row: { eventId: string }) => {
        seen.add(row.eventId);
        return { error: null };
      });
      return chain;
    },
  }),
}));

import { POST } from "@/app/api/stripe/webhook/route";

const SECRET = "whsec_test_secret";

function sign(body: string, secret = SECRET, ts = Math.floor(Date.now() / 1000)) {
  const v1 = createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");
  return `t=${ts},v1=${v1}`;
}

function makeReq(body: string, sig: string | null) {
  const headers: Record<string, string> = {};
  if (sig) headers["stripe-signature"] = sig;
  return new Request("http://localhost/api/stripe/webhook", {
    method: "POST",
    body,
    headers,
  });
}

describe("Stripe webhook", () => {
  beforeEach(() => {
    seen.clear();
    handleWebhookMock.mockReset();
    state.queriedEventId = "";
    process.env.STRIPE_WEBHOOK_SECRET = SECRET;
  });

  it("rejects a missing signature with 400", async () => {
    const res = await POST(makeReq('{"id":"evt_1"}', null));
    expect(res.status).toBe(400);
    expect(handleWebhookMock).not.toHaveBeenCalled();
  });

  it("rejects an invalid signature with 400", async () => {
    const res = await POST(
      makeReq('{"id":"evt_1"}', "t=0,v1=deadbeef")
    );
    expect(res.status).toBe(400);
    expect(handleWebhookMock).not.toHaveBeenCalled();
  });

  it("rejects a replayed/stale timestamp (outside ±300s)", async () => {
    const old = Math.floor(Date.now() / 1000) - 400; // > 300s ago
    const res = await POST(makeReq('{"id":"evt_1"}', sign('{"id":"evt_1"}', SECRET, old)));
    expect(res.status).toBe(400);
    expect(handleWebhookMock).not.toHaveBeenCalled();
  });

  it("accepts a valid signature and processes the event once", async () => {
    const body = '{"id":"evt_abc","type":"checkout.session.completed"}';
    const res = await POST(makeReq(body, sign(body)));
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.received).toBe(true);
    expect(handleWebhookMock).toHaveBeenCalledTimes(1);
    expect(handleWebhookMock.mock.calls[0][0]).toMatchObject({
      id: "evt_abc",
      type: "checkout.session.completed",
    });
  });

  it("is idempotent: a replayed event is not processed twice", async () => {
    const body = '{"id":"evt_xyz","type":"invoice.paid"}';
    const first = await POST(makeReq(body, sign(body)));
    expect(first.status).toBe(200);
    expect(handleWebhookMock).toHaveBeenCalledTimes(1);

    const second = await POST(makeReq(body, sign(body)));
    expect(second.status).toBe(200);
    const json = await second.json();
    expect(json.duplicate).toBe(true);
    // Still only processed once across both deliveries.
    expect(handleWebhookMock).toHaveBeenCalledTimes(1);
  });
});
