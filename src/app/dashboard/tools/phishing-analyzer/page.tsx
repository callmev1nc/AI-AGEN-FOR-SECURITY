"use client";

import ToolPageShell from "@/components/tools/ToolPageShell";
import ToolInputForm from "@/components/tools/ToolInputForm";
import ToolResultsDisplay, { ScoreGauge, ToolError } from "@/components/tools/ToolResultsDisplay";
import { useToolPage } from "@/components/tools/useToolPage";
import { trpcClient } from "@/lib/trpc-client";

interface PhishingResult {
  score: number;
  verdict: string;
  redFlags: string[];
  suspiciousLinks: string[];
  explanation: string;
}

export default function PhishingAnalyzerPage() {
  const { result, loading, error, submit } = useToolPage<PhishingResult>((emailText) =>
    trpcClient.tools.phishingAnalyzer.mutate({ emailText })
  );

  const verdictColors: Record<string, string> = {
    Safe: "var(--accent)",
    Suspicious: "var(--medium)",
    "Likely Phishing": "var(--warning)",
    "Confirmed Phishing": "var(--critical)",
  };

  return (
    <ToolPageShell
      title="Phishing Email Analyzer"
      description="Paste an email to analyze it for phishing indicators, get a risk score, and detailed AI-powered verdict."
    >
      <ToolInputForm
        onSubmit={submit}
        placeholder="Paste the full email content here (headers + body)..."
        buttonLabel="Analyze Email"
        loading={loading}
        rows={10}
      />

      <ToolError error={error} />

      {result && (
        <ToolResultsDisplay>
          <div className="space-y-6">
            <div className="flex flex-wrap items-start gap-6">
              <ScoreGauge score={result.score} label="Phishing Score" />
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Verdict</p>
                <p
                  className="mt-1 text-lg font-bold"
                  style={{ color: verdictColors[result.verdict] || "var(--text-secondary)", fontFamily: "var(--font-jetbrains)" }}
                >
                  {result.verdict}
                </p>
              </div>
            </div>

            {result.redFlags.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Red Flags</p>
                <ul className="space-y-1">
                  {result.redFlags.map((flag, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <span className="mt-0.5 text-[var(--critical)]">&#x2022;</span>
                      {flag}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {result.suspiciousLinks.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Suspicious Links</p>
                <ul className="space-y-1">
                  {result.suspiciousLinks.map((link, i) => (
                    <li key={i} className="text-sm text-[var(--medium)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
                      {link}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <p className="mb-1 text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">AI Analysis</p>
              <p className="text-sm leading-relaxed text-[var(--text-secondary)]">{result.explanation}</p>
            </div>
          </div>
        </ToolResultsDisplay>
      )}
    </ToolPageShell>
  );
}
