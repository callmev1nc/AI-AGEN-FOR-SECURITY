"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { trpcClient } from "@/lib/trpc-client";

const PLANS = [
  {
    name: "Free",
    price: "$0",
    description: "For personal projects and experimentation.",
    features: [
      "5 scans per month",
      "Website scan type only",
      "Quick & Standard levels",
      "PDF report export",
      "Basic vulnerability detection",
    ],
    priceId: null,
    cta: "Get Started",
    href: "/dashboard/scans/new",
    popular: false,
  },
  {
    name: "Pro",
    price: "$29",
    period: "/month",
    description: "For professionals and small teams.",
    features: [
      "Unlimited scans",
      "All scan types (Website, API, Infrastructure)",
      "All scan levels (Quick, Standard, Deep)",
      "PDF + AI report generation",
      "Security Chat with scan results",
      "Advanced scanning (Prompt Injection, Auth Bypass)",
      "Priority support",
    ],
    priceId: "price_pro_monthly",
    cta: "Upgrade to Pro",
    href: "",
    popular: true,
  },
  {
    name: "Enterprise",
    price: "$99",
    period: "/month",
    description: "For organizations with advanced security needs.",
    features: [
      "Everything in Pro, plus:",
      "Up to 100 scans per hour",
      "AI-powered code audit with patches",
      "Custom integrations & webhooks",
      "Dedicated support & SLA",
      "SSO & team management",
    ],
    priceId: "price_enterprise_monthly",
    cta: "Contact Sales",
    href: "",
    popular: false,
  },
];

export default function PricingPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ plan: string } | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    trpcClient.auth.me.query()
      .then((data) => setUser(data as { plan: string }))
      .catch(() => setUser(null));
  }, []);

  async function handleCheckout(priceId: string) {
    if (!user) {
      router.push("/login");
      return;
    }
    setLoading(true);
    try {
      const { url } = await trpcClient.billing.createCheckout.mutate({ priceId });
      if (url) {
        window.location.assign(url);
      } else {
        alert("Failed to start checkout. Please try again.");
      }
    } catch {
      alert("Failed to start checkout. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#06080d]">
      <header className="border-b border-[var(--border)] px-6 py-4">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <Link href="/" className="text-lg font-bold tracking-tight text-[var(--accent)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
            SecureScan
          </Link>
          <div className="flex items-center gap-4">
            {user ? (
              <Link href="/dashboard" className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black">Dashboard</Link>
            ) : (
              <>
                <Link href="/login" className="text-sm text-[var(--text-secondary)] hover:text-white">Sign In</Link>
                <Link href="/register" className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black">Get Started</Link>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-20">
        <div className="text-center mb-16">
          <h1 className="text-4xl font-bold tracking-tight" style={{ fontFamily: "var(--font-jetbrains)" }}>
            Simple, Transparent Pricing
          </h1>
          <p className="mt-4 text-lg text-[var(--text-secondary)]">
            Choose the plan that fits your security needs.
          </p>
        </div>

        <div className="grid gap-8 md:grid-cols-3">
          {PLANS.map((plan) => (
            <div
              key={plan.name}
              className={`relative rounded-2xl border p-8 ${
                plan.popular
                  ? "border-[var(--accent)] bg-[var(--accent-dim)]"
                  : "border-[var(--border)] bg-[var(--bg-card)]"
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-[var(--accent)] px-4 py-1 text-xs font-semibold text-black">
                  Most Popular
                </div>
              )}
              <h2 className="text-xl font-bold">{plan.name}</h2>
              <div className="mt-4 flex items-baseline gap-1">
                <span className="text-4xl font-bold">{plan.price}</span>
                {plan.period && <span className="text-sm text-[var(--text-muted)]">{plan.period}</span>}
              </div>
              <p className="mt-2 text-sm text-[var(--text-secondary)]">{plan.description}</p>

              <ul className="mt-6 space-y-3">
                {plan.features.map((feature, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-[var(--text-secondary)]">
                    <span className="mt-0.5 text-[var(--accent)]">✓</span>
                    {feature}
                  </li>
                ))}
              </ul>

              <button
                onClick={() => {
                  if (plan.priceId) {
                    handleCheckout(plan.priceId);
                  } else if (plan.href) {
                    router.push(plan.href);
                  }
                }}
                disabled={loading}
                className={`mt-8 w-full rounded-xl py-3 text-sm font-semibold transition-all ${
                  plan.popular
                    ? "bg-[var(--accent)] text-black hover:brightness-110"
                    : "border border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--accent-dim)] hover:text-white"
                } disabled:opacity-50`}
              >
                {plan.priceId && user?.plan === "pro" && plan.name === "Pro" ? "Current Plan" : plan.cta}
              </button>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
