"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { trpcClient } from "@/lib/trpc-client";

const scanLevels = [
  {
    id: "quick" as const,
    name: "Quick",
    time: "~15 seconds",
    modules: 5,
    color: "var(--accent)",
    colorClass: "border-[var(--accent)]",
    dotClass: "bg-[var(--accent)]",
    desc: "Passive security checks. Zero risk to production.",
    checks: [
      "Security Headers",
      "SSL/TLS Certificate",
      "Cookie Security",
      "Information Disclosure",
      "Mixed Content",
    ],
  },
  {
    id: "standard" as const,
    name: "Standard",
    time: "~30 seconds",
    modules: 7,
    color: "var(--medium)",
    colorClass: "border-[var(--medium)]",
    dotClass: "bg-[var(--medium)]",
    desc: "Active testing with safe payloads. Recommended for most sites.",
    featured: true,
    checks: [
      "Everything in Quick, plus:",
      "CORS Misconfiguration",
      "XSS Detection (Reflected)",
    ],
  },
  {
    id: "deep" as const,
    name: "Deep",
    time: "~1-3 minutes",
    modules: 13,
    color: "var(--critical)",
    colorClass: "border-[var(--critical)]",
    dotClass: "bg-[var(--critical)]",
    desc: "Full pentest simulation. Aggressive testing enabled.",
    checks: [
      "Everything in Standard, plus:",
      "Port Scanning (top 100)",
      "Advanced XSS (DOM + Mutation)",
      "CORS Origin Bypass",
      "Cookie Analysis",
      "Error Page Fuzzing",
      "Header Fuzzing (CRLF)",
    ],
  },
];

export default function NewScanPage() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [level, setLevel] = useState<"quick" | "standard" | "deep">("standard");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    let normalizedUrl = url;
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = "https://" + normalizedUrl;
    }

    try {
      new URL(normalizedUrl);
    } catch {
      setError("Please enter a valid URL");
      return;
    }

    setLoading(true);
    try {
      const scan = await trpcClient.scan.create.mutate({
        targetUrl: normalizedUrl,
        scanLevel: level,
      });
      router.push(`/dashboard/scans/${scan.id}`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to create scan";
      setError(message);
      setLoading(false);
    }
  }

  return (
    <div className="animate-fade-in-up mx-auto max-w-3xl space-y-8">
      {/* Header */}
      <div>
        <div className="mb-2 flex items-center gap-2 text-sm text-[var(--text-muted)]">
          <Link href="/dashboard" className="hover:text-white transition-colors">
            Dashboard
          </Link>
          <span>/</span>
          <span>New Scan</span>
        </div>
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          New Security Scan
        </h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Enter a URL and choose your scan depth to get started.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-8">
        {/* URL Input */}
        <div>
          <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-[var(--text-secondary)]">
            Target URL
          </label>
          <div className="relative">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4 text-[var(--text-muted)]">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
              </svg>
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
              placeholder="https://example.com"
              className="w-full rounded-xl border border-[var(--border)] bg-[var(--bg-card)] py-3.5 pl-11 pr-4 text-sm text-white placeholder:text-[var(--text-muted)] outline-none transition-all focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent-dim)] font-[family-name:var(--font-jetbrains)]"
            />
          </div>
          {error && (
            <p className="mt-2 text-xs text-[var(--critical)]">{error}</p>
          )}
        </div>

        {/* Scan Level Selector */}
        <div>
          <label className="mb-3 block text-xs font-medium uppercase tracking-wider text-[var(--text-secondary)]">
            Scan Level
          </label>
          <div className="grid gap-4 sm:grid-cols-3">
            {scanLevels.map((l) => (
              <button
                key={l.id}
                type="button"
                onClick={() => setLevel(l.id)}
                className={`relative rounded-xl border p-5 text-left transition-all ${
                  level === l.id
                    ? "border-[var(--accent)] bg-[var(--accent-dim)]"
                    : "border-[var(--border)] bg-[var(--bg-card)] hover:border-[var(--accent-dim)] hover:bg-[var(--bg-card-hover)]"
                }`}
              >
                {l.featured && level !== l.id && (
                  <div className="absolute -top-2.5 left-1/2 -translate-x-1/2 rounded-full bg-[var(--bg-card)] px-2 py-0.5 text-[10px] font-medium text-[var(--text-muted)] border border-[var(--border)]">
                    Popular
                  </div>
                )}
                {level === l.id && (
                  <div className="absolute -top-2.5 left-1/2 -translate-x-1/2 rounded-full bg-[var(--accent)] px-2 py-0.5 text-[10px] font-semibold text-black">
                    Selected
                  </div>
                )}
                <div className="flex items-center gap-2">
                  <div className={`h-2 w-2 rounded-full ${l.dotClass}`} />
                  <span
                    className="text-xs font-semibold uppercase tracking-widest"
                    style={{ color: l.color, fontFamily: "var(--font-jetbrains)" }}
                  >
                    {l.name}
                  </span>
                </div>
                <div className="mt-2 text-xl font-bold">{l.time}</div>
                <div className="text-xs text-[var(--text-muted)]">
                  {l.modules} modules
                </div>
                <p className="mt-3 text-xs leading-relaxed text-[var(--text-secondary)]">
                  {l.desc}
                </p>
                <ul className="mt-3 space-y-1">
                  {l.checks.map((check, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-1.5 text-xs text-[var(--text-muted)]"
                    >
                      <span className="mt-0.5 text-[var(--accent)]">✓</span>
                      {check}
                    </li>
                  ))}
                </ul>
              </button>
            ))}
          </div>
        </div>

        {/* Submit */}
        <div className="flex items-center gap-4">
          <button
            type="submit"
            disabled={loading}
            className="rounded-xl bg-[var(--accent)] px-8 py-3 text-sm font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-black/30 border-t-black" />
                Starting scan...
              </span>
            ) : (
              "Start Scan"
            )}
          </button>
          <Link
            href="/dashboard"
            className="text-sm text-[var(--text-muted)] transition-colors hover:text-white"
          >
            Cancel
          </Link>
        </div>
      </form>
    </div>
  );
}
