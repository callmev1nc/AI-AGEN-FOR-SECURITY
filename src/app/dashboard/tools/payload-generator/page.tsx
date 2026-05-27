"use client";

import { useState } from "react";
import ToolPageShell from "@/components/tools/ToolPageShell";
import ToolResultsDisplay, { CodeBlock } from "@/components/tools/ToolResultsDisplay";
import { trpcClient } from "@/lib/trpc-client";

interface PayloadItem {
  payload: string;
  type: string;
  riskLevel: string;
  description: string;
}

interface PayloadGeneratorResult {
  payloads: PayloadItem[];
  disclaimer: string;
  warnings: string[];
}

const VULN_TYPE = ["sql-injection", "xss", "path-traversal", "command-injection", "nosql-injection", "ldap-injection", "xxe", "ssrf"] as const;
type VulnType = typeof VULN_TYPE[number];

const VULNERABILITY_OPTIONS: Array<{ value: VulnType; label: string }> = [
  { value: "sql-injection", label: "SQL Injection" },
  { value: "xss", label: "Cross-Site Scripting (XSS)" },
  { value: "path-traversal", label: "Path Traversal" },
  { value: "command-injection", label: "OS Command Injection" },
  { value: "nosql-injection", label: "NoSQL Injection" },
  { value: "ldap-injection", label: "LDAP Injection" },
  { value: "xxe", label: "XML External Entity (XXE)" },
  { value: "ssrf", label: "Server-Side Request Forgery (SSRF)" },
];

export default function PayloadGeneratorPage() {
  const [description, setDescription] = useState("");
  const [endpointType, setEndpointType] = useState<"rest" | "web-form" | "graphql">("rest");
  const [vulnTypes, setVulnTypes] = useState<VulnType[]>([]);
  const [result, setResult] = useState<PayloadGeneratorResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  function toggleVulnType(value: VulnType) {
    setVulnTypes((prev) =>
      prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!description.trim() || vulnTypes.length === 0) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await trpcClient.tools.payloadGenerator.mutate({
        endpointDescription: description.trim(),
        endpointType,
        vulnerabilityTypes: vulnTypes,
      });
      setResult(data as PayloadGeneratorResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Payload generation failed");
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
      title="Ethical Payload Generator"
      description="Generate authorized testing payloads for common vulnerability types. For authorized security testing only."
    >
      <div className="rounded-lg border border-[var(--warning-dim)] bg-[var(--warning-dim)]/10 px-4 py-3">
        <p className="text-xs font-semibold uppercase tracking-wider text-[var(--warning)]">Legal Disclaimer</p>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Only use generated payloads against systems you own or have explicit written authorization to test.
          Unauthorized use of these payloads may violate computer fraud laws.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="card-base space-y-4 p-5">
        <div>
          <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Endpoint Description
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe the endpoint to test...&#10;&#10;Example: POST /api/users/login with JSON body { username, password } returns a JWT token"
            maxLength={5000}
            rows={4}
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] px-4 py-3 text-sm text-white placeholder-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)] resize-y"
            disabled={loading}
          />
        </div>

        <div>
          <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Endpoint Type
          </label>
          <div className="flex gap-2">
            {["rest", "web-form", "graphql"].map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setEndpointType(t as "rest" | "web-form" | "graphql")}
                className={`rounded-lg px-4 py-2 text-sm font-medium transition-all ${
                  endpointType === t
                    ? "bg-[var(--accent)] text-black"
                    : "bg-[var(--bg-card-hover)] text-[var(--text-secondary)] hover:brightness-110"
                }`}
              >
                {t === "rest" ? "REST API" : t === "web-form" ? "Web Form" : "GraphQL"}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Vulnerability Types
          </label>
          <div className="flex flex-wrap gap-2">
            {VULNERABILITY_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => toggleVulnType(opt.value)}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${
                  vulnTypes.includes(opt.value)
                    ? "bg-[var(--accent)] text-black"
                    : "bg-[var(--bg-card-hover)] text-[var(--text-secondary)] hover:brightness-110"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !description.trim() || vulnTypes.length === 0}
          className="rounded-lg bg-[var(--accent)] px-6 py-2.5 text-sm font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Generating..." : "Generate Payloads"}
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
            {result.disclaimer && (
              <div className="rounded-lg border border-[var(--warning-dim)] bg-[var(--warning-dim)]/10 px-4 py-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-[var(--warning)]">Disclaimer</p>
                <p className="mt-1 text-sm text-[var(--text-secondary)]">{result.disclaimer}</p>
              </div>
            )}

            {result.warnings.length > 0 && (
              <div className="rounded-lg border border-[var(--critical-dim)] bg-[var(--critical-dim)]/10 px-4 py-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-[var(--critical)]">Warnings</p>
                <ul className="mt-1 space-y-1">
                  {result.warnings.map((w, i) => (
                    <li key={i} className="text-sm text-[var(--text-secondary)]">{w}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="space-y-4">
              {result.payloads.map((item, i) => (
                <div key={i} className="rounded-lg border border-[var(--border)] p-4">
                  <div className="mb-2 flex items-center gap-2">
                    <span className="rounded bg-[var(--accent-dim)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
                      {item.type}
                    </span>
                    <span
                      className="rounded px-2 py-0.5 text-[10px] font-semibold"
                      style={{ backgroundColor: `${riskColors[item.riskLevel]}20`, color: riskColors[item.riskLevel], fontFamily: "var(--font-jetbrains)" }}
                    >
                      {item.riskLevel}
                    </span>
                  </div>
                  <CodeBlock code={item.payload} language={endpointType.toUpperCase()} />
                  <p className="mt-2 text-xs text-[var(--text-secondary)]">{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </ToolResultsDisplay>
      )}
    </ToolPageShell>
  );
}
