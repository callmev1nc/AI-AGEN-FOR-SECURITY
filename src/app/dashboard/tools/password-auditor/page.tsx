"use client";

import { useState } from "react";
import ToolPageShell from "@/components/tools/ToolPageShell";
import ToolInputForm from "@/components/tools/ToolInputForm";
import ToolResultsDisplay, { ScoreGauge } from "@/components/tools/ToolResultsDisplay";
import { trpcClient } from "@/lib/trpc-client";

interface PolicyIssue {
  category: string;
  finding: string;
  severity: string;
  recommendation: string;
  nistReference: string;
}

interface PasswordPolicyResult {
  complianceScore: number;
  issues: PolicyIssue[];
  strengths: string[];
  overallAssessment: string;
}

export default function PasswordAuditorPage() {
  const [result, setResult] = useState<PasswordPolicyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(policyText: string) {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await trpcClient.tools.passwordAuditor.mutate({ policyText });
      setResult(data as PasswordPolicyResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Audit failed");
    } finally {
      setLoading(false);
    }
  }

  const severityColors: Record<string, string> = {
    critical: "var(--critical)",
    high: "var(--critical)",
    medium: "var(--medium)",
    low: "var(--info)",
    info: "var(--text-muted)",
  };

  return (
    <ToolPageShell
      title="Password Policy Auditor"
      description="Paste your organization's password policy to audit it against NIST SP 800-63B guidelines and get a compliance score."
    >
      <ToolInputForm
        onSubmit={handleSubmit}
        placeholder={`Paste your password policy text here...\n\nExample:\n- Passwords must be at least 12 characters\n- Must contain uppercase, lowercase, number, and special character\n- Passwords expire every 90 days\n- Cannot reuse last 5 passwords`}
        buttonLabel="Audit Policy"
        loading={loading}
        rows={8}
      />

      {error && (
        <div className="rounded-lg border border-[#ef4444]/30 bg-[#ef4444]/10 px-4 py-3 text-sm text-[#ef4444]">
          {error}
        </div>
      )}

      {result && (
        <ToolResultsDisplay>
          <div className="space-y-6">
            <div className="flex flex-wrap items-start gap-6">
              <ScoreGauge score={result.complianceScore} label="NIST Compliance" higherIsWorse={false} />
            </div>

            <p className="text-sm leading-relaxed text-[var(--text-secondary)]">{result.overallAssessment}</p>

            {result.strengths.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wider text-[var(--accent)]">Strengths</p>
                <ul className="space-y-1">
                  {result.strengths.map((s, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-[var(--text-secondary)]">
                      <span className="mt-0.5 text-[var(--accent)]">&#x2713;</span>
                      {s}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {result.issues.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wider text-[var(--critical)]">Issues Found</p>
                <div className="space-y-3">
                  {result.issues.map((issue, i) => (
                    <div key={i} className="rounded-lg border border-[var(--border)] p-4">
                      <div className="flex items-start gap-2">
                        <span
                          className="mt-0.5 inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase"
                          style={{ backgroundColor: `${severityColors[issue.severity]}20`, color: severityColors[issue.severity], fontFamily: "var(--font-jetbrains)" }}
                        >
                          {issue.severity}
                        </span>
                        <div className="flex-1">
                          <p className="text-sm font-medium">{issue.category}</p>
                          <p className="mt-1 text-xs text-[var(--text-secondary)]">{issue.finding}</p>
                          <p className="mt-1 text-xs text-[var(--accent)]">Recommendation: {issue.recommendation}</p>
                          <p className="mt-0.5 text-[10px] text-[var(--text-muted)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
                            {issue.nistReference}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </ToolResultsDisplay>
      )}
    </ToolPageShell>
  );
}
