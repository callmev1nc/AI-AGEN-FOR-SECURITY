import { handleWebhook } from "@/server/services/billing";
import { logger } from "@/lib/logger";
import { createHmac } from "crypto";

function verifyStripeSignature(body: string, signature: string, secret: string): boolean {
  const parts = signature.split(",");
  let timestamp = "";
  let v1Signature = "";
  for (const part of parts) {
    const [key, value] = part.split("=");
    if (key === "t") timestamp = value;
    if (key === "v1") v1Signature = value;
  }
  if (!timestamp || !v1Signature) return false;

  const age = Math.floor(Date.now() / 1000) - Number(timestamp);
  if (age > 300 || age < -300) return false;

  const expected = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
  return expected === v1Signature;
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
    await handleWebhook(event);

    return Response.json({ received: true });
  } catch (err) {
    logger.error("StripeWebhook", `Webhook error: ${err}`);
    return Response.json({ error: "Webhook handler failed" }, { status: 500 });
  }
}
