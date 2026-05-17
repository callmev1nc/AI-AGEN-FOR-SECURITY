import Link from "next/link";

// Mock data for demo — will be replaced with tRPC data
const mockScan = {
  id: "demo-1",
  targetUrl: "https://example.com",
  status: "completed" as const,
  scanLevel: "standard" as const,
  overallScore: 62,
  createdAt: new Date(),
  vulnerabilities: [
    {
      id: "v1",
      severity: "critical" as const,
      category: "xss",
      title: "Reflected XSS in search parameter",
      description:
        "The search parameter reflects user input without proper encoding, allowing script injection.",
      evidence: 'Payload: <script>alert(1)</script> reflected in response body at line 42.',
      remediation:
        "Encode all user input before rendering in HTML. Use context-aware encoding (HTML, JavaScript, URL).",
      affectedUrl: "https://example.com/search?q=",
    },
    {
      id: "v2",
      severity: "high" as const,
      category: "cors",
      title: "CORS allows any origin with credentials",
      description:
        "The server responds with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.",
      evidence: "Response header: Access-Control-Allow-Origin: *",
      remediation:
        "Restrict allowed origins to trusted domains. Never combine wildcard origin with credentials.",
      affectedUrl: "https://example.com/api/",
    },
    {
      id: "v3",
      severity: "high" as const,
      category: "cors",
      title: "Origin reflection without validation",
      description:
        "The server reflects the Origin header in Access-Control-Allow-Origin without validation.",
      evidence: "Request Origin: evil.com → Response ACAC: true, ACAO: evil.com",
      remediation:
        "Maintain an allowlist of permitted origins. Validate Origin against this list before reflecting.",
      affectedUrl: "https://example.com/api/data",
    },
    {
      id: "v4",
      severity: "medium" as const,
      category: "headers",
      title: "Missing Content-Security-Policy header",
      description:
        "The response does not include a Content-Security-Policy header, leaving the page vulnerable to XSS and data injection.",
      evidence: "Response headers do not include Content-Security-Policy.",
      remediation:
        "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'",
      affectedUrl: "https://example.com/",
    },
    {
      id: "v5",
      severity: "medium" as const,
      category: "headers",
      title: "Missing Strict-Transport-Security header",
      description:
        "The server does not send HSTS headers, allowing protocol downgrade attacks.",
      evidence: "Response headers do not include Strict-Transport-Security.",
      remediation:
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      affectedUrl: "https://example.com/",
    },
    {
      id: "v6",
      severity: "low" as const,
      category: "headers",
      title: "Missing X-Content-Type-Options header",
      description:
        "The X-Content-Type-Options header is not set, allowing MIME-type sniffing.",
      evidence: "Response headers do not include X-Content-Type-Options.",
      remediation: 'Add: X-Content-Type-Options: nosniff',
      affectedUrl: "https://example.com/",
    },
    {
      id: "v7",
      severity: "info" as const,
      category: "info-disclosure",
      title: "Server version disclosed",
      description:
        "The Server header reveals version information that could help attackers identify known vulnerabilities.",
      evidence: "Server: nginx/1.18.0 (Ubuntu)",
      remediation:
        "Remove or obfuscate the Server header. Configure server_tokens off in nginx.",
      affectedUrl: "https://example.com/",
    },
  ],
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

export default function ScanResultsPage() {
  const scan = mockScan;
  const scoreColor = getScoreColor(scan.overallScore);
  const vulns = scan.vulnerabilities;

  const severityCounts = {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
    info: vulns.filter((v) => v.severity === "info").length,
  };

  return (
    <div className="animate-fade-in-up space-y-8">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-[var(--text-muted)]">
        <Link href="/dashboard" className="hover:text-white transition-colors">
          Dashboard
        </Link>
        <span>/</span>
        <Link href="/dashboard/scans/new" className="hover:text-white transition-colors">
          Scans
        </Link>
        <span>/</span>
        <span className="text-[var(--text-secondary)]">Results</span>
      </div>

      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1
            className="text-2xl font-bold tracking-tight"
            style={{ fontFamily: "var(--font-jetbrains)" }}
          >
            Scan Results
          </h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            {scan.targetUrl} —{" "}
            <span className="uppercase font-medium" style={{ fontFamily: "var(--font-jetbrains)" }}>
              {scan.scanLevel}
            </span>{" "}
            scan
          </p>
        </div>
        <div className="flex gap-3">
          <button className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-white">
            Export PDF
          </button>
          <Link
            href="/dashboard/scans/new"
            className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110"
          >
            New Scan
          </Link>
        </div>
      </div>

      {/* Score + Severity cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
        {/* Score gauge */}
        <div className="card-base col-span-2 flex items-center gap-6 p-6">
          <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
            <svg className="h-24 w-24 -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="42"
                stroke="var(--border)"
                strokeWidth="6"
                fill="none"
              />
              <circle
                cx="50"
                cy="50"
                r="42"
                stroke={scoreColor}
                strokeWidth="6"
                fill="none"
                strokeDasharray={`${(scan.overallScore / 100) * 264} 264`}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute flex flex-col items-center">
              <span
                className="text-2xl font-bold"
                style={{ color: scoreColor, fontFamily: "var(--font-jetbrains)" }}
              >
                {scan.overallScore}
              </span>
            </div>
          </div>
          <div>
            <div
              className="text-lg font-bold"
              style={{ color: scoreColor }}
            >
              {getScoreLabel(scan.overallScore)}
            </div>
            <div className="mt-1 text-sm text-[var(--text-secondary)]">
              {vulns.length} findings total
            </div>
            <div className="mt-1 text-xs text-[var(--text-muted)]">
              {new Date(scan.createdAt).toLocaleDateString()}
            </div>
          </div>
        </div>

        {/* Severity breakdown */}
        {(["critical", "high", "medium", "low"] as const).map((sev) => {
          const colors = getSeverityColor(sev);
          const count = severityCounts[sev];
          return (
            <div key={sev} className="card-base p-4">
              <div className="flex items-center gap-2">
                <div
                  className="h-2 w-2 rounded-full"
                  style={{ background: colors.border }}
                />
                <span className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  {sev}
                </span>
              </div>
              <div className="mt-2 text-3xl font-bold" style={{ color: colors.text }}>
                {count}
              </div>
            </div>
          );
        })}

        {/* Info */}
        <div className="card-base p-4">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-[var(--info)]" />
            <span className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
              info
            </span>
          </div>
          <div className="mt-2 text-3xl font-bold text-[var(--info)]">
            {severityCounts.info}
          </div>
        </div>
      </div>

      {/* Vulnerability list */}
      <div>
        <h2
          className="mb-4 text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          Vulnerability Findings ({vulns.length})
        </h2>
        <div className="space-y-3">
          {vulns.map((vuln) => {
            const colors = getSeverityColor(vuln.severity);
            return (
              <details
                key={vuln.id}
                className="card-base group cursor-pointer"
              >
                <summary className="flex items-center gap-4 p-4 list-none [&::-webkit-details-marker]:hidden">
                  <div
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ background: colors.border }}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-3">
                      <span className="font-medium text-sm">{vuln.title}</span>
                      <span
                        className="shrink-0 rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider"
                        style={{
                          background: colors.bg,
                          color: colors.text,
                          fontFamily: "var(--font-jetbrains)",
                        }}
                      >
                        {vuln.severity}
                      </span>
                      <span className="shrink-0 rounded border border-[var(--border)] px-2 py-0.5 text-[10px] text-[var(--text-muted)] uppercase tracking-wider" style={{ fontFamily: "var(--font-jetbrains)" }}>
                        {vuln.category}
                      </span>
                    </div>
                  </div>
                  <svg
                    className="h-4 w-4 shrink-0 text-[var(--text-muted)] transition-transform group-open:rotate-180"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path d="M19 9l-7 7-7-7" />
                  </svg>
                </summary>
                <div className="border-t border-[var(--border)] px-4 pb-4 pt-3 space-y-4">
                  <div>
                    <div className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] mb-1">
                      Description
                    </div>
                    <p className="text-sm leading-relaxed text-[var(--text-secondary)]">
                      {vuln.description}
                    </p>
                  </div>
                  {vuln.evidence && (
                    <div>
                      <div className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] mb-1">
                        Evidence
                      </div>
                      <div className="rounded-lg bg-[#0a0e14] border border-[var(--border)] p-3 font-[family-name:var(--font-jetbrains)] text-xs leading-relaxed text-[var(--text-secondary)]">
                        {vuln.evidence}
                      </div>
                    </div>
                  )}
                  <div>
                    <div className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] mb-1">
                      Remediation
                    </div>
                    <p className="text-sm leading-relaxed text-[var(--accent)]">
                      {vuln.remediation}
                    </p>
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
    </div>
  );
}
