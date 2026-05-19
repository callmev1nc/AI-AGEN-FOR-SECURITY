"use client";

import { useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { trpcClient } from "@/lib/trpc-client";

type Vulnerability = {
  id: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  evidence: string | null;
  remediation: string;
  affectedUrl: string;
};

type Scan = {
  id: string;
  targetUrl: string;
  status: string;
  scanLevel: string;
  overallScore: number | null;
  progressPercent: number | null;
  currentModule: string | null;
  modulesCompleted: number | null;
  totalModules: number | null;
  errorMessage: string | null;
  createdAt: string;
  vulnerabilities: Vulnerability[];
};

function getScoreColor(score: number) {
  if (score >= 80) return "var(--accent)";
  if (score >= 50) return "var(--medium)";
  return "var(--critical)";
}

function getScoreLabel(score: number) {
  if (score >= 80) return "Good";
  if (score >= 50) return "Needs Attention";
  return "Critical Risk";
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case "critical": return { bg: "var(--critical-dim)", text: "var(--critical)", border: "var(--critical)" };
    case "high": return { bg: "var(--high-dim)", text: "var(--high)", border: "var(--high)" };
    case "medium": return { bg: "var(--medium-dim)", text: "var(--medium)", border: "var(--medium)" };
    case "low": return { bg: "var(--low-dim)", text: "var(--low)", border: "var(--low)" };
    default: return { bg: "var(--info-dim)", text: "var(--info)", border: "var(--info)" };
  }
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function ScanProgress({ scan }: { scan: Scan }) {
  const percent = scan.progressPercent ?? 0;
  const done = scan.modulesCompleted ?? 0;
  const total = scan.totalModules ?? 0;
  const moduleName = scan.currentModule ?? "Working...";

  const [elapsed, setElapsed] = useState(0);
  const startedAtRef = useRef<number | null>(null);

  useEffect(() => {
    if (scan.status !== "running" && scan.status !== "queued") return;
    startedAtRef.current = Date.now();
    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAtRef.current!) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [scan.status]);

  const estTotal = percent > 0 ? Math.floor((elapsed / percent) * 100) : 0;
  const remaining = Math.max(0, estTotal - elapsed);

  return (
    <div className="animate-fade-in-up mx-auto flex min-h-[50vh] max-w-2xl items-center justify-center">
      <div className="w-full space-y-6">
        <div className="text-center">
          <h2 className="text-lg font-bold" style={{ fontFamily: "var(--font-jetbrains)" }}>
            {scan.status === "queued" ? "Scan queued" : "Scan in progress"}
          </h2>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            {scan.targetUrl} &mdash;{" "}
            <span className="uppercase font-medium">{scan.scanLevel}</span> scan
          </p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)]">
            <span>{done} of {total} modules completed</span>
            <span>{percent}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--border)]">
            <div
              className="h-full rounded-full bg-[var(--accent)] transition-all duration-500 ease-out"
              style={{ width: `${percent}%` }}
            />
          </div>
        </div>

        {scan.status === "running" && (
          <div className="card-base flex items-center gap-3 p-4">
            <div className="h-3 w-3 animate-spin rounded-full border-2 border-[var(--accent-dim)] border-t-[var(--accent)] shrink-0" />
            <div>
              <p className="text-sm font-medium text-[var(--text-secondary)]">{moduleName}</p>
              {remaining > 0 && (
                <p className="text-xs text-[var(--text-muted)]">
                  Estimated {formatDuration(remaining)} remaining
                </p>
              )}
            </div>
          </div>
        )}

        {scan.status === "queued" && (
          <div className="card-base flex items-center gap-3 p-4">
            <div className="h-3 w-3 animate-pulse rounded-full bg-[var(--medium)] shrink-0" />
            <p className="text-sm text-[var(--text-secondary)]">
              Starting scan...
            </p>
          </div>
        )}

        {scan.errorMessage && (
          <div className="rounded-lg border border-[var(--critical-dim)] bg-[var(--critical-dim)] p-3 text-sm text-[var(--critical)]">
            Scanner error: {scan.errorMessage}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScanResultsPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const triggerSent = useRef(false);

  useEffect(() => {
    trpcClient.scan.byId.query({ id: scanId })
      .then((data) => {
        setScan(data as Scan);
        setLoading(false);
      })
      .catch((err: Error) => {
        setError(err.message);
        setLoading(false);
      });
  }, [scanId]);

  useEffect(() => {
    if (!scan || scan.status !== "queued" || triggerSent.current) return;
    triggerSent.current = true;
    fetch("/api/scan/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scanId: scan.id }),
    }).catch(() => {});
  }, [scan]);

  useEffect(() => {
    if (!scan || (scan.status !== "queued" && scan.status !== "running")) return;
    const interval = setInterval(async () => {
      try {
        const data = await trpcClient.scan.byId.query({ id: scanId });
        setScan(data as Scan);
      } catch {
        // silently retry
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [scan, scanId]);

  if (loading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mx-auto mb-4 h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent-dim)] border-t-[var(--accent)]" />
          <p className="text-sm text-[var(--text-muted)]">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <div className="text-center">
          <p className="text-sm text-[var(--critical)]">{error || "Scan not found"}</p>
          <Link href="/dashboard" className="mt-4 inline-block text-sm text-[var(--accent)] hover:underline">
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  if (scan.status === "queued" || scan.status === "running") {
    return <ScanProgress scan={scan} />;
  }

  const vulns = scan.vulnerabilities || [];
  const score = scan.overallScore ?? 0;
  const scoreColor = getScoreColor(score);

  const severityCounts = {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
    info: vulns.filter((v) => v.severity === "info").length,
  };

  return (
    <div className="animate-fade-in-up space-y-8">
      <div className="flex items-center gap-2 text-sm text-[var(--text-muted)]">
        <Link href="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
        <span>/</span>
        <Link href="/dashboard/scans/new" className="hover:text-white transition-colors">Scans</Link>
        <span>/</span>
        <span className="text-[var(--text-secondary)]">Results</span>
      </div>

      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ fontFamily: "var(--font-jetbrains)" }}>Scan Results</h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            {scan.targetUrl} &mdash;{" "}
            <span className="uppercase font-medium" style={{ fontFamily: "var(--font-jetbrains)" }}>{scan.scanLevel}</span> scan
          </p>
        </div>
        <div className="flex gap-3">
          <button className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-white">
            Export PDF
          </button>
          <Link href="/dashboard/scans/new" className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110">New Scan</Link>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
        <div className="card-base col-span-2 flex items-center gap-6 p-6">
          <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
            <svg className="h-24 w-24 -rotate-90" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="42" stroke="var(--border)" strokeWidth="6" fill="none" />
              <circle cx="50" cy="50" r="42" stroke={scoreColor} strokeWidth="6" fill="none"
                strokeDasharray={`${(score / 100) * 264} 264`} strokeLinecap="round" />
            </svg>
            <div className="absolute flex flex-col items-center">
              <span className="text-2xl font-bold" style={{ color: scoreColor, fontFamily: "var(--font-jetbrains)" }}>{score}</span>
            </div>
          </div>
          <div>
            <div className="text-lg font-bold" style={{ color: scoreColor }}>{getScoreLabel(score)}</div>
            <div className="mt-1 text-sm text-[var(--text-secondary)]">{vulns.length} findings total</div>
            <div className="mt-1 text-xs text-[var(--text-muted)]">{new Date(scan.createdAt).toLocaleDateString()}</div>
          </div>
        </div>

        {(["critical", "high", "medium", "low"] as const).map((sev) => {
          const colors = getSeverityColor(sev);
          const count = severityCounts[sev];
          return (
            <div key={sev} className="card-base p-4">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full" style={{ background: colors.border }} />
                <span className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">{sev}</span>
              </div>
              <div className="mt-2 text-3xl font-bold" style={{ color: colors.text }}>{count}</div>
            </div>
          );
        })}

        <div className="card-base p-4">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-[var(--info)]" />
            <span className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">info</span>
          </div>
          <div className="mt-2 text-3xl font-bold text-[var(--info)]">{severityCounts.info}</div>
        </div>
      </div>

      {vulns.length === 0 ? (
        <div className="card-base flex items-center justify-center py-12 text-[var(--text-muted)]">
          <div className="text-center">
            <p className="text-sm">No vulnerabilities found</p>
            <p className="mt-1 text-xs">This scan did not detect any security issues.</p>
          </div>
        </div>
      ) : (
        <div>
          <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
            Vulnerability Findings ({vulns.length})
          </h2>
          <div className="space-y-3">
            {vulns.map((vuln) => {
              const colors = getSeverityColor(vuln.severity);
              return (
                <details key={vuln.id} className="card-base group cursor-pointer">
                  <summary className="flex items-center gap-4 p-4 list-none [&::-webkit-details-marker]:hidden">
                    <div className="h-2 w-2 shrink-0 rounded-full" style={{ background: colors.border }} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <span className="font-medium text-sm">{vuln.title}</span>
                        <span className="shrink-0 rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider"
                          style={{ background: colors.bg, color: colors.text, fontFamily: "var(--font-jetbrains)" }}>
                          {vuln.severity}
                        </span>
                        <span className="shrink-0 rounded border border-[var(--border)] px-2 py-0.5 text-[10px] text-[var(--text-muted)] uppercase tracking-wider"
                          style={{ fontFamily: "var(--font-jetbrains)" }}>
                          {vuln.category}
                        </span>
                      </div>
                    </div>
                    <svg className="h-4 w-4 shrink-0 text-[var(--text-muted)] transition-transform group-open:rotate-180"
                      viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M19 9l-7 7-7-7" />
                    </svg>
                  </summary>
                  <div className="border-t border-[var(--border)] px-4 pb-4 pt-3 space-y-4">
                    <div>
                      <div className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] mb-1">Description</div>
                      <p className="text-sm leading-relaxed text-[var(--text-secondary)]">{vuln.description}</p>
                    </div>
                    {vuln.evidence && (
                      <div>
                        <div className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] mb-1">Evidence</div>
                        <div className="rounded-lg bg-[#0a0e14] border border-[var(--border)] p-3 font-[family-name:var(--font-jetbrains)] text-xs leading-relaxed text-[var(--text-secondary)]">
                          {vuln.evidence}
                        </div>
                      </div>
                    )}
                    <div>
                      <div className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] mb-1">Remediation</div>
                      <p className="text-sm leading-relaxed text-[var(--accent)]">{vuln.remediation}</p>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-[var(--text-muted)]">
                      <span>Affected: {vuln.affectedUrl}</span>
                    </div>
                  </div>
                </details>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
