"use client";

import { useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { trpcClient } from "@/lib/trpc-client";
import ChatPanel from "./chat-panel";

type Vulnerability = {
  id: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  evidence: string | null;
  remediation: string;
  affectedUrl: string;
  cvssScore?: number | null;
};

type Scan = {
  id: string;
  targetUrl: string;
  status: string;
  scanLevel: string;
  scanType: string;
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

function downloadBlob(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportScanJson(scan: Scan) {
  const payload = {
    scan: {
      id: scan.id,
      targetUrl: scan.targetUrl,
      scanType: scan.scanType,
      scanLevel: scan.scanLevel,
      overallScore: scan.overallScore,
      createdAt: scan.createdAt,
    },
    vulnerabilities: scan.vulnerabilities ?? [],
    exportedAt: new Date().toISOString(),
  };
  downloadBlob(`scan-${scan.id}.json`, JSON.stringify(payload, null, 2), "application/json");
}

function exportScanCsv(scan: Scan) {
  const header = ["severity", "category", "title", "affectedUrl", "cvssScore", "description", "remediation"];
  const esc = (v: unknown) =>
    `"${String(v ?? "").replace(/"/g, '""').replace(/[\r\n]+/g, " ")}"`;
  const rows = [header.map(esc).join(",")];
  for (const v of scan.vulnerabilities ?? []) {
    rows.push(
      [v.severity, v.category, v.title, v.affectedUrl, v.cvssScore ?? "", v.description, v.remediation]
        .map(esc)
        .join(",")
    );
  }
  downloadBlob(`scan-${scan.id}.csv`, rows.join("\n"), "text/csv");
}

function sarifLevel(severity: string): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function exportScanSarif(scan: Scan) {
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: { name: "SecureScan", informationUri: "https://securescan.app" },
        },
        results: (scan.vulnerabilities ?? []).map((v) => ({
          ruleId: v.category,
          level: sarifLevel(v.severity),
          message: { text: `${v.title} — ${v.description}` },
          locations: [
            { physicalLocation: { artifactLocation: { uri: v.affectedUrl } } },
          ],
        })),
      },
    ],
  };
  downloadBlob(`scan-${scan.id}.sarif`, JSON.stringify(sarif, null, 2), "application/json");
}

function MarkdownBlock({ content }: { content: string }) {
  return (
    <div className="prose prose-invert prose-sm max-w-none">
      {content.split("\n").map((line, i) => {
        if (line.startsWith("# ")) return <h1 key={i} className="text-lg font-bold mt-4 mb-2">{line.slice(2)}</h1>;
        if (line.startsWith("## ")) return <h2 key={i} className="text-base font-bold mt-3 mb-1">{line.slice(3)}</h2>;
        if (line.startsWith("### ")) return <h3 key={i} className="text-sm font-bold mt-2 mb-1">{line.slice(4)}</h3>;
        if (line.startsWith("**") && line.endsWith("**")) return <p key={i} className="font-semibold text-[var(--text-secondary)] mt-2">{line.slice(2, -2)}</p>;
        if (line.trim() === "") return <div key={i} className="h-2" />;
        if (line.startsWith("- ")) return <li key={i} className="text-sm text-[var(--text-secondary)] ml-4 list-disc">{line.slice(2)}</li>;
        if (/^\d+\. /.test(line)) return <li key={i} className="text-sm text-[var(--text-secondary)] ml-4 list-decimal">{line.slice(line.indexOf(".") + 2)}</li>;
        return <p key={i} className="text-sm text-[var(--text-secondary)]">{line}</p>;
      })}
    </div>
  );
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
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [aiReportLoading, setAiReportLoading] = useState(false);
  const [aiReportError, setAiReportError] = useState("");
  const [exploitChain, setExploitChain] = useState<string | null>(null);
  const [exploitChainLoading, setExploitChainLoading] = useState(false);
  const [exploitChainError, setExploitChainError] = useState("");
  const triggerSent = useRef(false);
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [diff, setDiff] = useState<{
    hasBaseline: boolean;
    baselineCreatedAt?: string;
    addedCount?: number;
    resolvedCount?: number;
    persistedCount?: number;
  } | null>(null);

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

  useEffect(() => {
    if (!scan || scan.status !== "completed") return;
    trpcClient.scan.diff
      .query({ scanId })
      .then(setDiff)
      .catch(() => {
        /* differential is best-effort; never block the page */
      });
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
  const filteredVulns = sevFilter === "all" ? vulns : vulns.filter((v) => v.severity === sevFilter);
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
        <Link href="/dashboard" className="hover:text-[var(--text-primary)] transition-colors">Dashboard</Link>
        <span>/</span>
        <Link href="/dashboard/scans/new" className="hover:text-[var(--text-primary)] transition-colors">Scans</Link>
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
        <div className="flex flex-col items-end gap-2">
          {exportError && (
            <p className="text-xs text-[var(--critical)]">{exportError}</p>
          )}
          <div className="flex gap-3">
          <button
            onClick={async () => {
              setExporting(true);
              setExportError("");
              try {
                const { downloadUrl } = await trpcClient.scan.exportPdf.mutate({ id: scanId });
                const a = document.createElement("a");
                a.href = downloadUrl;
                a.download = `security-report-${scanId}.pdf`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
              } catch (err) {
                setExportError(err instanceof Error ? err.message : "Export failed");
              } finally {
                setExporting(false);
              }
            }}
            disabled={exporting}
            className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-[var(--text-primary)] disabled:opacity-50"
          >
            {exporting ? "Exporting..." : "Export PDF"}
          </button>
          <button
            onClick={() => exportScanJson(scan)}
            className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-[var(--text-primary)]"
          >
            Export JSON
          </button>
          <button
            onClick={() => exportScanCsv(scan)}
            className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-[var(--text-primary)]"
          >
            Export CSV
          </button>
          <button
            onClick={() => exportScanSarif(scan)}
            className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-[var(--text-primary)]"
          >
            Export SARIF
          </button>
          <button
            onClick={async () => {
              setAiReportLoading(true);
              setAiReportError("");
              try {
                const result = await trpcClient.scan.generateAiReport.mutate({ id: scanId });
                setAiReport(result.content);
              } catch (err) {
                setAiReportError(err instanceof Error ? err.message : "Failed to generate AI report");
              } finally {
                setAiReportLoading(false);
              }
            }}
            disabled={aiReportLoading}
            className="rounded-lg border border-[var(--accent-dim)] px-4 py-2 text-sm text-[var(--accent)] transition-colors hover:bg-[var(--accent-dim)] disabled:opacity-50"
          >
            {aiReportLoading ? "Generating..." : "Generate AI Report"}
          </button>
          <button
            onClick={async () => {
              setExploitChainLoading(true);
              setExploitChainError("");
              try {
                const result = await trpcClient.scan.generateExploitChain.mutate({ id: scanId });
                setExploitChain(result.content);
              } catch (err) {
                setExploitChainError(err instanceof Error ? err.message : "Failed to generate exploit-chain analysis");
              } finally {
                setExploitChainLoading(false);
              }
            }}
            disabled={exploitChainLoading}
            className="rounded-lg border border-[var(--critical-dim)] px-4 py-2 text-sm text-[var(--critical)] transition-colors hover:bg-[var(--critical-dim)] disabled:opacity-50"
          >
            {exploitChainLoading ? "Analyzing..." : "Exploit-Chain Analysis"}
          </button>
          <Link href="/dashboard/scans/new" className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110">New Scan</Link>
        </div>
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

      {diff?.hasBaseline && (
        <div className="card-base flex flex-wrap items-center gap-x-8 gap-y-2 p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
            vs previous scan
            {diff.baselineCreatedAt ? ` (${new Date(diff.baselineCreatedAt).toLocaleDateString()})` : ""}
          </p>
          <span className="text-sm font-semibold text-[var(--critical)]">+{diff.addedCount} new</span>
          <span className="text-sm font-semibold text-[var(--accent)]">&minus;{diff.resolvedCount} resolved</span>
          <span className="text-sm text-[var(--text-muted)]">{diff.persistedCount} unchanged</span>
        </div>
      )}

      {vulns.length === 0 ? (
        <div className="card-base flex items-center justify-center py-12 text-[var(--text-muted)]">
          <div className="text-center">
            <p className="text-sm">No vulnerabilities found</p>
            <p className="mt-1 text-xs">This scan did not detect any security issues.</p>
          </div>
        </div>
      ) : (
        <div>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
              Vulnerability Findings ({filteredVulns.length}{sevFilter !== "all" ? ` of ${vulns.length}` : ""})
            </h2>
            <div className="flex flex-wrap gap-1.5">
              {["all", "critical", "high", "medium", "low", "info"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSevFilter(sev)}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-medium uppercase tracking-wider transition-colors ${
                    sevFilter === sev
                      ? "bg-[var(--accent-dim)] text-[var(--accent)]"
                      : "border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {sev === "all" ? "All" : sev}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-3">
            {filteredVulns.length === 0 && (
              <p className="card-base px-4 py-6 text-center text-sm text-[var(--text-muted)]">
                No findings match this filter.
              </p>
            )}
            {filteredVulns.map((vuln) => {
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

      {(aiReport || aiReportError) && (
        <div className="card-base overflow-hidden">
          <div className="flex items-center justify-between border-b border-[var(--border)] p-4">
            <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
              AI-Generated Pentest Report
            </h2>
            {aiReport && (
              <button
                onClick={() => setAiReport(null)}
                className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
              >
                Close
              </button>
            )}
          </div>
          <div className="p-4">
            {aiReportError && (
              <p className="text-sm text-[var(--critical)]">{aiReportError}</p>
            )}
            {aiReport && <MarkdownBlock content={aiReport} />}
          </div>
        </div>
      )}

      {(exploitChain || exploitChainError) && (
        <div className="card-base overflow-hidden">
          <div className="flex items-center justify-between border-b border-[var(--border)] p-4">
            <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
              Exploit-Chain Analysis
            </h2>
            {exploitChain && (
              <button onClick={() => setExploitChain(null)} className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
                Close
              </button>
            )}
          </div>
          <div className="p-4">
            {exploitChainError && <p className="text-sm text-[var(--critical)]">{exploitChainError}</p>}
            {exploitChain && <MarkdownBlock content={exploitChain} />}
          </div>
        </div>
      )}

      <div className="card-base overflow-hidden">
        <ChatPanel scanId={scanId} />
      </div>
    </div>
  );
}
