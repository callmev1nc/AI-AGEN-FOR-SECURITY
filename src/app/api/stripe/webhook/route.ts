import { handleWebhook } from "@/server/services/billing";
import { logger } from "@/lib/logger";
import { createAdminClient } from "@/lib/supabase/admin";
import { createHmac, timingSafeEqual } from "crypto";

/**
 * Verify a Stripe webhook signature (StripeSigningScheme: t=...,v1=...).
 * - Robust parse: uses indexOf("=") so signature segments containing "="
 *   survive (split("=") would corrupt them).
 * - Constant-time HMAC comparison to avoid timing side-channels.
 * - Rejects timestamps outside ±300s (replay window) per Stripe guidance.
 */
function verifyStripeSignature(body: string, signature: string, secret: string): boolean {
  let timestamp = "";
  let v1Signature = "";
  for (const part of signature.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1);
    if (key === "t") timestamp = value;
    else if (key === "v1") v1Signature = value;
  }
  if (!timestamp || !v1Signature) return false;

  const age = Math.floor(Date.now() / 1000) - Number(timestamp);
  if (Number.isNaN(age) || age > 300 || age < -300) return false;

  const expected = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(v1Signature);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export async function POST(req: Request) {
  try {
    const body = await req.text();
    const signature = req.headers.get("stripe-signature");

    if (!signature) {
      return Response.json({ error: "Missing stripe-signature header" }, { status: 400 });
    }

    const secret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!secret) {
      logger.error("StripeWebhook", "STRIPE_WEBHOOK_SECRET not configured");
      return Response.json({ error: "Webhook secret not configured" }, { status: 500 });
    }

    if (!verifyStripeSignature(body, signature, secret)) {
      logger.error("StripeWebhook", "Invalid webhook signature");
      return Response.json({ error: "Invalid signature" }, { status: 400 });
    }

    const event = JSON.parse(body);

    // Idempotency: Stripe may redeliver the same event. Skip if already seen.
    const eventId = typeof event?.id === "string" ? event.id : null;
    if (eventId) {
      const admin = createAdminClient();
      const { data: existing } = await admin
        .from("stripe_events")
        .select("eventId")
        .eq("eventId", eventId)
        .maybeSingle();
      if (existing) {
        return Response.json({ received: true, duplicate: true });
      }
      await handleWebhook(event);
      await admin.from("stripe_events").upsert(
        {
          eventId,
          type: typeof event?.type === "string" ? event.type : null,
        },
        { onConflict: "eventId" }
      );
    } else {
      await handleWebhook(event);
    }

    return Response.json({ received: true });
  } catch (err) {
    logger.error("StripeWebhook", `Webhook error: ${err}`);
    return Response.json({ error: "Webhook handler failed" }, { status: 500 });
  }
}
