"use client";

import ToolPageShell from "@/components/tools/ToolPageShell";
import ToolInputForm from "@/components/tools/ToolInputForm";
import ToolResultsDisplay, { ScoreGauge, CopyButton, ToolError } from "@/components/tools/ToolResultsDisplay";
import { useToolPage } from "@/components/tools/useToolPage";
import { trpcClient } from "@/lib/trpc-client";

interface HeaderFinding {
  header: string;
  status: "present" | "missing" | "weak";
  value: string | null;
  recommendation: string;
}

interface HeaderAnalysisResult {
  score: number;
  targetUrl: string;
  findings: HeaderFinding[];
  missingHeaders: string[];
  aiRecommendations: string;
}

export default function HeadersAnalyzerPage() {
  const { result, loading, error, submit } = useToolPage<HeaderAnalysisResult>((rawUrl) => {
    const url = rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`;
    try {
      new URL(url);
    } catch {
      throw new Error("Invalid URL format");
    }
    return trpcClient.tools.headersAnalyzer.mutate({ targetUrl: url });
  });

  const statusColors: Record<string, string> = {
    present: "var(--accent)",
    missing: "var(--critical)",
    weak: "var(--warning)",
  };

  return (
    <ToolPageShell
      title="HTTP Security Headers Analyzer"
      description="Enter a URL to analyze its HTTP security headers. Get a score, detailed findings, and AI-powered recommendations."
    >
      <ToolInputForm
        onSubmit={submit}
        placeholder="Enter a URL (e.g. https://example.com)..."
        buttonLabel="Analyze Headers"
        loading={loading}
        rows={2}
        maxLength={2048}
      />

      <ToolError error={error} />

      {result && (
        <ToolResultsDisplay>
          <div className="space-y-6">
            <div className="flex flex-wrap items-start gap-6">
              <ScoreGauge score={result.score} label="Header Score" higherIsWorse={false} />
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Target</p>
                <p className="mt-1 text-sm" style={{ fontFamily: "var(--font-jetbrains)" }}>{result.targetUrl}</p>
                <p className="mt-2 text-xs text-[var(--text-muted)]">
                  {result.findings.filter((f) => f.status === "present").length} of {result.findings.length} headers present
                </p>
              </div>
            </div>

            <div className="space-y-2">
              {result.findings.map((finding, i) => (
                <div key={i} className="flex items-start gap-3 rounded-lg border border-[var(--border)] p-3">
                  <span
                    className="mt-0.5 inline-block h-2.5 w-2.5 shrink-0 rounded-full"
                    style={{ backgroundColor: statusColors[finding.status] }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium" style={{ fontFamily: "var(--font-jetbrains)" }}>
                        {finding.header}
                      </span>
                      <span
                        className="rounded px-2 py-0.5 text-[10px] font-semibold uppercase"
                        style={{ backgroundColor: `${statusColors[finding.status]}20`, color: statusColors[finding.status] }}
                      >
                        {finding.status}
                      </span>
                    </div>
                    {finding.value && (
                      <p className="mt-0.5 text-xs text-[var(--text-muted)] break-all" style={{ fontFamily: "var(--font-jetbrains)" }}>
                        {finding.value}
                      </p>
                    )}
                    <p className="mt-1 text-xs text-[var(--text-secondary)]">{finding.recommendation}</p>
                  </div>
                </div>
              ))}
            </div>

            <div>
              <p className="mb-2 text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">AI Recommendations</p>
              <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-4">
                <p className="text-sm leading-relaxed text-[var(--text-secondary)] whitespace-pre-wrap">{result.aiRecommendations}</p>
              </div>
            </div>
          </div>
        </ToolResultsDisplay>
      )}
    </ToolPageShell>
  );
}
