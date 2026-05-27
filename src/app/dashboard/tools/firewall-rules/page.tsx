"use client";

import { useState } from "react";
import ToolPageShell from "@/components/tools/ToolPageShell";
import ToolResultsDisplay, { CodeBlock, CopyButton } from "@/components/tools/ToolResultsDisplay";
import { trpcClient } from "@/lib/trpc-client";

interface FirewallRule {
  rule: string;
  description: string;
  riskLevel: string;
}

interface FirewallRulesResult {
  rules: FirewallRule[];
  explanation: string;
  warnings: string[];
}

export default function FirewallRulesPage() {
  const [description, setDescription] = useState("");
  const [platform, setPlatform] = useState<"iptables" | "ufw" | "aws">("iptables");
  const [result, setResult] = useState<FirewallRulesResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!description.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await trpcClient.tools.firewallRules.mutate({ description: description.trim(), platform });
      setResult(data as FirewallRulesResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Rule generation failed");
    } finally {
      setLoading(false);
    }
  }

  const riskColors: Record<string, string> = {
    low: "var(--accent)",
    medium: "var(--warning)",
    high: "var(--critical)",
  };

  return (
    <ToolPageShell
      title="Plain English to Firewall Rules"
      description="Describe your firewall requirements in plain English and get generated rules for iptables, UFW, or AWS Security Groups."
    >
      <form onSubmit={handleSubmit} className="card-base space-y-4 p-5">
        <div>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe your firewall needs in plain English...&#10;&#10;Example: Allow HTTPS traffic from the internet to my web server at 10.0.0.1, allow SSH only from the office IP 203.0.113.5, block all other inbound traffic."
            maxLength={5000}
            rows={6}
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] px-4 py-3 text-sm text-white placeholder-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)] resize-y"
            disabled={loading}
          />
        </div>
        <div>
          <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Platform
          </label>
          <div className="flex gap-2">
            {(["iptables", "ufw", "aws"] as const).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setPlatform(p)}
                className={`rounded-lg px-4 py-2 text-sm font-medium transition-all ${
                  platform === p
                    ? "bg-[var(--accent)] text-black"
                    : "bg-[var(--bg-card-hover)] text-[var(--text-secondary)] hover:brightness-110"
                }`}
              >
                {p.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
        <button
          type="submit"
          disabled={loading || !description.trim()}
          className="rounded-lg bg-[var(--accent)] px-6 py-2.5 text-sm font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Generating..." : "Generate Rules"}
        </button>
      </form>

      {error && (
        <div className="rounded-lg border border-[#ef4444]/30 bg-[#ef4444]/10 px-4 py-3 text-sm text-[#ef4444]">
          {error}
        </div>
      )}

      {result && (
        <ToolResultsDisplay>
          <div className="space-y-6">
            {result.explanation && (
              <p className="text-sm text-[var(--text-secondary)]">{result.explanation}</p>
            )}

            {result.warnings.length > 0 && (
              <div className="rounded-lg border border-[var(--warning-dim)] bg-[var(--warning-dim)]/10 px-4 py-3">
                <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-[var(--warning)]">Warnings</p>
                <ul className="space-y-1">
                  {result.warnings.map((w, i) => (
                    <li key={i} className="text-sm text-[var(--text-secondary)]">{w}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="space-y-4">
              {result.rules.map((rule, i) => (
                <div key={i} className="rounded-lg border border-[var(--border)] p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">Rule {i + 1}</span>
                        <span
                          className="rounded px-2 py-0.5 text-[10px] font-semibold"
                          style={{ backgroundColor: `${riskColors[rule.riskLevel]}20`, color: riskColors[rule.riskLevel], fontFamily: "var(--font-jetbrains)" }}
                        >
                          {rule.riskLevel}
                        </span>
                      </div>
                      <CodeBlock code={rule.rule} language={platform.toUpperCase()} />
                      <p className="mt-2 text-xs text-[var(--text-secondary)]">{rule.description}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </ToolResultsDisplay>
      )}
    </ToolPageShell>
  );
}
