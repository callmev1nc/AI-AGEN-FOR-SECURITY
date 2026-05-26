"use client";

import { useState, useEffect, useCallback } from "react";
import { trpcClient } from "@/lib/trpc-client";

interface UserProfile {
  id: string;
  email: string;
  name: string;
  plan: string;
}

export default function SettingsPage() {
  const [name, setName] = useState("");
  const [originalName, setOriginalName] = useState("");
  const [email, setEmail] = useState("");
  const [plan, setPlan] = useState("free");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const [portalLoading, setPortalLoading] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const data = (await trpcClient.auth.me.query()) as UserProfile | null;
        if (data) {
          setName(data.name);
          setOriginalName(data.name);
          setEmail(data.email);
          setPlan(data.plan);
        }
      } catch {
        setError("Failed to load profile");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleSave = useCallback(async () => {
    setSaving(true);
    setError("");
    setSaved(false);
    try {
      await trpcClient.auth.updateProfile.mutate({ name });
      setOriginalName(name);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }, [name]);

  if (loading) {
    return (
      <div className="animate-fade-in-up mx-auto max-w-2xl space-y-8">
        <div>
          <h1
            className="text-2xl font-bold tracking-tight"
            style={{ fontFamily: "var(--font-jetbrains)" }}
          >
            Settings
          </h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Manage your account and preferences.
          </p>
        </div>
        <div className="card-base flex items-center justify-center p-12">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent" />
        </div>
      </div>
    );
  }

  return (
    <div className="animate-fade-in-up mx-auto max-w-2xl space-y-8">
      <div>
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          Settings
        </h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Manage your account and preferences.
        </p>
      </div>

      {/* Profile */}
      <div className="card-base p-6 space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Profile
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-[var(--text-secondary)]">
              Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-4 py-2.5 text-sm text-white placeholder:text-[var(--text-muted)] outline-none transition-colors focus:border-[var(--accent)]"
              placeholder="Your name"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-[var(--text-secondary)]">
              Email
            </label>
            <input
              type="email"
              value={email}
              disabled
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-4 py-2.5 text-sm text-white opacity-60 outline-none"
            />
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              Contact support to change your email address.
            </p>
          </div>
        </div>

        {error && (
          <p className="text-xs text-[#ef4444]">{error}</p>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={handleSave}
            disabled={saving || name === originalName || name.trim().length === 0}
            className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? "Saving..." : "Save Changes"}
          </button>
          {saved && (
            <span className="text-xs text-[var(--accent)]">Saved!</span>
          )}
        </div>
      </div>

      {/* API Keys */}
      <div className="card-base p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
            API Keys
          </h2>
          <button className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-white">
            Generate New Key
          </button>
        </div>
        <p className="text-sm text-[var(--text-secondary)]">
          Use API keys to run scans programmatically.
        </p>
        <div className="rounded-lg border border-[var(--border)] bg-[#0a0e14] p-4 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-muted)]">
          No API keys generated yet.
        </div>
      </div>

      {/* Billing */}
      <div className="card-base p-6 space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Billing
        </h2>
        <div className="flex items-center justify-between rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
          <div>
            <div className="text-sm font-medium capitalize">{plan} Plan</div>
            <div className="text-xs text-[var(--text-muted)]">
              {plan === "free" ? "5 scans per hour" : plan === "pro" ? "30 scans per hour" : "100 scans per hour"}
            </div>
          </div>
          <span className="rounded-lg border border-[var(--accent-dim)] bg-[var(--accent-dim)] px-3 py-1 text-xs font-medium text-[var(--accent)]">
            Current Plan
          </span>
        </div>
        <div className="flex gap-3">
          {plan === "free" && (
            <button
              onClick={() => window.location.href = "/pricing"}
              className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110"
            >
              Upgrade Plan
            </button>
          )}
          {(plan === "pro" || plan === "enterprise") && (
            <button
              onClick={async () => {
                setPortalLoading(true);
                try {
                  const { url } = await trpcClient.billing.createPortal.mutate();
                  if (url) window.location.href = url;
                } catch {
                  // handled by finally
                } finally {
                  setPortalLoading(false);
                }
              }}
              disabled={portalLoading}
              className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-white disabled:opacity-50"
            >
              {portalLoading ? "Loading..." : "Manage Billing"}
            </button>
          )}
        </div>
        {typeof window !== "undefined" && new URLSearchParams(window.location.search).get("checkout") === "success" && (
          <div className="rounded-lg bg-[var(--accent-dim)] p-3 text-sm text-[var(--accent)]">
            Welcome to Pro! Your plan has been upgraded successfully.
          </div>
        )}
      </div>
    </div>
  );
}
