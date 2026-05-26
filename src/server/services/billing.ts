import { createAdminClient } from "@/lib/supabase/admin";
import { logger } from "@/lib/logger";

const STRIPE_API = "https://api.stripe.com/v1";

function getStripeHeaders(): Record<string, string> {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY is not set");
  return {
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };
}

async function stripePost(path: string, data: Record<string, unknown>) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(data)) {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const item = value[i] as Record<string, unknown>;
        for (const [subKey, subValue] of Object.entries(item)) {
          body.append(`${key}[${i}][${subKey}]`, String(subValue));
        }
      }
    } else if (typeof value === "object" && value !== null) {
      for (const [subKey, subValue] of Object.entries(value as Record<string, unknown>)) {
        body.append(`${key}[${subKey}]`, String(subValue));
      }
    } else {
      body.append(key, String(value));
    }
  }
  const res = await fetch(`${STRIPE_API}${path}`, {
    method: "POST",
    headers: getStripeHeaders(),
    body,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Stripe API error (${res.status}): ${err}`);
  }
  return res.json();
}

// stripeGet is available for future use
// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function stripeGet(path: string) {
  const res = await fetch(`${STRIPE_API}${path}`, {
    headers: getStripeHeaders(),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Stripe API error (${res.status}): ${err}`);
  }
  return res.json();
}

const VALID_PRICE_IDS = new Set([
  process.env.STRIPE_PRO_PRICE_ID,
  process.env.STRIPE_ENTERPRISE_PRICE_ID,
].filter(Boolean));

export async function createCheckoutSession(userId: string, priceId: string) {
  if (!VALID_PRICE_IDS.has(priceId)) {
    throw new Error("Invalid price ID");
  }
  const admin = createAdminClient();

  const { data: user } = await admin
    .from("users")
    .select("id, email, name, stripeCustomerId")
    .eq("id", userId)
    .single();

  if (!user) throw new Error("User not found");

  let customerId = user.stripeCustomerId;

  if (!customerId) {
    const customer = await stripePost("/customers", {
      email: user.email,
      name: user.name,
      metadata: { userId },
    });
    customerId = customer.id;

    await admin.from("users").update({ stripeCustomerId: customerId }).eq("id", userId);
  }

  const session = await stripePost("/checkout/sessions", {
    customer: customerId,
    mode: "subscription",
    line_items: [{ price: priceId, quantity: "1" }],
    success_url: `${process.env.NEXT_PUBLIC_APP_URL}/dashboard/settings?checkout=success`,
    cancel_url: `${process.env.NEXT_PUBLIC_APP_URL}/pricing`,
    metadata: { userId },
  });

  return { url: session.url, sessionId: session.id };
}

export async function createBillingPortalSession(userId: string) {
  const admin = createAdminClient();

  const { data: user } = await admin
    .from("users")
    .select("stripeCustomerId")
    .eq("id", userId)
    .single();

  if (!user?.stripeCustomerId) throw new Error("No Stripe customer found");

  const session = await stripePost("/billing_portal/sessions", {
    customer: user.stripeCustomerId,
    return_url: `${process.env.NEXT_PUBLIC_APP_URL}/dashboard/settings`,
  });

  return { url: session.url };
}

export async function handleWebhook(event: {
  type: string;
  data: { object: { customer?: string; metadata?: Record<string, string>; status?: string; plan?: { product?: string } } };
}) {
  const admin = createAdminClient();

  logger.info("Billing", `Processing webhook: ${event.type}`);

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object;
      const userId = session.metadata?.userId;
      if (!userId) break;

      const { error: updateError } = await admin
        .from("users")
        .update({ plan: "pro" })
        .eq("id", userId);
      if (updateError) throw new Error(`Failed to update plan: ${updateError.message}`);
      break;
    }

    case "customer.subscription.updated":
    case "customer.subscription.deleted": {
      const subscription = event.data.object;
      const customerId = subscription.customer;
      if (!customerId) break;

      const { data: user } = await admin
        .from("users")
        .select("id")
        .eq("stripeCustomerId", customerId)
        .single();

      if (!user) break;

      const plan = subscription.status === "active" ? "pro" : "free";
      const { error: subUpdateError } = await admin
        .from("users")
        .update({ plan })
        .eq("id", user.id);
      if (subUpdateError) throw new Error(`Failed to update plan: ${subUpdateError.message}`);
      break;
    }
  }
}

export async function getPlanLimits(plan: string): Promise<{ scansPerHour: number }> {
  switch (plan) {
    case "enterprise":
      return { scansPerHour: 100 };
    case "pro":
      return { scansPerHour: 30 };
    default:
      return { scansPerHour: 5 };
  }
}
