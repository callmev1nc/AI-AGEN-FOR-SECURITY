"use client";

import Link from "next/link";

const toolCards = [
  {
    slug: "phishing-analyzer",
    name: "Phishing Email Analyzer",
    description: "Analyze email text for phishing indicators, score suspiciousness, and get AI-powered verdicts.",
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
      </svg>
    ),
  },
  {
    slug: "cve-explainer",
    name: "CVE Plain-English Explainer",
    description: "Fetch any CVE and get a plain-English explanation, severity, affected products, and remediation steps.",
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="10" />
        <path d="M12 16v-4M12 8h.01" />
      </svg>
    ),
  },
  {
    slug: "secrets-scanner",
    name: "Secrets / .env Leak Scanner",
    description: "Scan code or text for hardcoded secrets, API keys, and credentials using regex + AI triage.",
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
      </svg>
    ),
  },
  {
    slug: "firewall-rules",
    name: "Plain English to Firewall Rules",
    description: "Describe your firewall needs in plain English and get generated iptables, UFW, or AWS Security Group rules.",
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
  {
    slug: "password-auditor",
    name: "Password Policy Auditor",
    description: "Audit your password policy against NIST 800-63B guidelines with compliance scores and recommendations.",
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  {
    slug: "payload-generator",
    name: "Ethical Payload Generator",
    description: "Generate authorized testing payloads for SQLi, XSS, path traversal, and more with disclaimers.",
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
      </svg>
    ),
  },
  {
    slug: "headers-analyzer",
    name: "HTTP Security Headers Analyzer",
    description: "Check a website's security headers, get a score, and AI-powered recommendations for missing headers.",
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7" />
      </svg>
    ),
  },
];

export default function ToolsLandingPage() {
  return (
    <div className="animate-fade-in-up space-y-8">
      <div>
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          Security Tools
        </h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          A collection of AI-powered cybersecurity utilities to help you analyze, audit, and secure your infrastructure.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {toolCards.map((tool) => (
          <Link
            key={tool.slug}
            href={`/dashboard/tools/${tool.slug}`}
            className="card-base group p-5 transition-all hover:border-[var(--accent)] hover:shadow-md"
          >
            <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--accent-dim)] text-[var(--accent)] group-hover:brightness-110 transition-all">
              {tool.icon}
            </div>
            <h3 className="mb-1 text-sm font-semibold group-hover:text-[var(--accent)] transition-colors">
              {tool.name}
            </h3>
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              {tool.description}
            </p>
          </Link>
        ))}
      </div>
    </div>
  );
}
