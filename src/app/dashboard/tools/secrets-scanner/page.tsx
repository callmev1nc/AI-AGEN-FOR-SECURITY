"use client";

import ToolPageShell from "@/components/tools/ToolPageShell";
import ToolInputForm from "@/components/tools/ToolInputForm";
import ToolResultsDisplay, { CopyButton, ToolError } from "@/components/tools/ToolResultsDisplay";
import { useToolPage } from "@/components/tools/useToolPage";
import { trpcClient } from "@/lib/trpc-client";

interface SecretsFinding {
  lineNumber: number;
  match: string;
  patternName: string;
  severity: string;
  context: string;
  isFalsePositive: boolean;
  confidence: number;
}

interface SecretsResult {
  findings: SecretsFinding[];
  summary: string;
}

export default function SecretsScannerPage() {
  const { result, loading, error, submit } = useToolPage<SecretsResult>((content) =>
    trpcClient.tools.secretsScanner.mutate({ content })
  );

  const severityColors: Record<string, string> = {
    critical: "var(--critical)",
    high: "var(--medium)",
    medium: "var(--warning)",
    low: "var(--info)",
    info: "var(--text-muted)",
  };

  return (
    <ToolPageShell
      title="Secrets / .env Leak Scanner"
      description="Paste code or configuration files to scan for hardcoded secrets, API keys, tokens, and credentials. Uses regex patterns plus AI false-positive triage."
    >
      <ToolInputForm
        onSubmit={submit}
        placeholder={`Paste code, config files, or .env contents here...\n\nExample:\nDB_PASSWORD=supersecret123\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE`}
        buttonLabel="Scan for Secrets"
        loading={loading}
        rows={10}
      />

      <ToolError error={error} />

      {result && (
        <ToolResultsDisplay>
          <div className="space-y-6">
            <p className="text-sm text-[var(--text-secondary)]">{result.summary}</p>

            {result.findings.length === 0 && (
              <p className="text-sm text-[var(--accent)]">No secrets detected.</p>
            )}

            {result.findings.map((finding, i) => (
              <div key={i} className={`rounded-lg border p-4 ${finding.isFalsePositive ? "border-[var(--info-dim)] opacity-60" : "border-[var(--border)]"}`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className="inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase"
                        style={{ backgroundColor: `${severityColors[finding.severity]}20`, color: severityColors[finding.severity], fontFamily: "var(--font-jetbrains)" }}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-sm font-medium">{finding.patternName}</span>
                      {finding.isFalsePositive && (
                        <span className="rounded bg-[var(--info-dim)] px-2 py-0.5 text-[10px] font-semibold text-[var(--info)]">
                          False Positive
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-xs text-[var(--text-muted)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
                      Line {finding.lineNumber} | Match: {finding.match}
                    </p>
                    <p className="mt-1 text-xs text-[var(--text-secondary)]">
                      Confidence: {finding.confidence}%
                    </p>
                  </div>
                </div>
                <pre className="mt-2 overflow-x-auto rounded bg-[var(--bg-primary)] p-3 text-xs leading-relaxed" style={{ fontFamily: "var(--font-jetbrains)" }}>
                  {finding.context}
                </pre>
              </div>
            ))}
          </div>
        </ToolResultsDisplay>
      )}
    </ToolPageShell>
  );
}
