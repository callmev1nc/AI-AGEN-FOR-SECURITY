import Link from "next/link";

export default function Home() {
  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* Background grid pattern */}
      <div
        className="pointer-events-none fixed inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(var(--accent) 1px, transparent 1px), linear-gradient(90deg, var(--accent) 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
        }}
      />
      {/* Gradient orbs */}
      <div className="pointer-events-none fixed top-[-20%] left-[-10%] h-[600px] w-[600px] rounded-full bg-[#10b98108] blur-[120px]" />
      <div className="pointer-events-none fixed bottom-[-20%] right-[-10%] h-[500px] w-[500px] rounded-full bg-[#3b82f608] blur-[120px]" />

      {/* Nav */}
      <nav className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent)]">
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              className="text-black"
            >
              <path
                d="M8 1L2 4.5V11.5L8 15L14 11.5V4.5L8 1Z"
                stroke="currentColor"
                strokeWidth="1.5"
                fill="none"
              />
              <path
                d="M8 1V15M2 4.5L8 8L14 4.5"
                stroke="currentColor"
                strokeWidth="1.5"
              />
            </svg>
          </div>
          <span className="font-[family-name:var(--font-jetbrains)] text-lg font-semibold tracking-tight">
            SecureScan
          </span>
        </div>
        <div className="flex items-center gap-6">
          <Link
            href="/login"
            className="text-sm text-[var(--text-secondary)] transition-colors hover:text-white"
          >
            Sign in
          </Link>
          <Link
            href="/register"
            className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-medium text-black transition-all hover:brightness-110"
          >
            Get Started
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <main className="relative z-10 mx-auto max-w-6xl px-6 pt-20 pb-32">
        <div className="animate-fade-in-up">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--bg-card)] px-4 py-1.5 text-xs text-[var(--text-secondary)]">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-[var(--accent)] animate-pulse" />
            Real-time vulnerability detection
          </div>
        </div>

        <h1
          className="animate-fade-in-up-delay-1 max-w-3xl text-5xl font-bold leading-[1.1] tracking-tight sm:text-6xl lg:text-7xl"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          Find vulnerabilities
          <br />
          <span className="text-[var(--accent)] text-glow">before attackers do</span>
        </h1>

        <p className="animate-fade-in-up-delay-2 mt-6 max-w-xl text-lg leading-relaxed text-[var(--text-secondary)]">
          Automated security audits for any website. Run 13+ security tests
          in seconds and get actionable reports with severity scores,
          evidence, and step-by-step remediation.
        </p>

        <div className="animate-fade-in-up-delay-3 mt-10 flex items-center gap-4">
          <Link
            href="/register"
            className="group relative rounded-xl bg-[var(--accent)] px-8 py-3.5 text-sm font-semibold text-black transition-all hover:brightness-110"
          >
            <span className="relative z-10">Start Free Scan</span>
            <div className="absolute inset-0 rounded-xl bg-[var(--accent)] opacity-0 blur-xl transition-opacity group-hover:opacity-40" />
          </Link>
          <Link
            href="/dashboard"
            className="rounded-xl border border-[var(--border)] px-8 py-3.5 text-sm font-medium text-[var(--text-secondary)] transition-all hover:border-[var(--accent-dim)] hover:text-white"
          >
            View Demo
          </Link>
        </div>

        {/* Terminal preview */}
        <div className="animate-fade-in-up-delay-3 mt-20 rounded-2xl border border-[var(--border)] bg-[var(--bg-secondary)] p-1">
          <div className="flex items-center gap-2 border-b border-[var(--border)] px-4 py-3">
            <div className="h-3 w-3 rounded-full bg-[#ef4444]" />
            <div className="h-3 w-3 rounded-full bg-[#f59e0b]" />
            <div className="h-3 w-3 rounded-full bg-[#10b981]" />
            <span className="ml-2 text-xs text-[var(--text-muted)] font-[family-name:var(--font-jetbrains)]">
              securescan — audit report
            </span>
          </div>
          <div className="p-6 font-[family-name:var(--font-jetbrains)] text-sm leading-7">
            <div className="text-[var(--text-muted)]">
              $ securescan scan https://example.com --level deep
            </div>
            <div className="mt-3 text-[var(--accent)]">
              [SCANNING] Running 13 security modules...
            </div>
            <div className="mt-1 text-[var(--text-secondary)]">
              <span className="text-[var(--accent)]">✓</span> Security
              Headers ............ 3 findings
            </div>
            <div className="text-[var(--text-secondary)]">
              <span className="text-[var(--accent)]">✓</span> SSL/TLS
              Certificate ......... 1 finding
            </div>
            <div className="text-[var(--text-secondary)]">
              <span className="text-[var(--high)]">!</span> CORS
              Misconfiguration .... 2 findings
            </div>
            <div className="text-[var(--text-secondary)]">
              <span className="text-[var(--critical)]">✗</span> XSS
              Vulnerability ....... 1 finding
            </div>
            <div className="text-[var(--text-secondary)]">
              <span className="text-[var(--accent)]">✓</span> Cookie
              Security ............ 0 findings
            </div>
            <div className="mt-3 border-t border-[var(--border)] pt-3">
              <span className="text-[var(--text-muted)]">
                Overall Security Score:{" "}
              </span>
              <span className="text-[var(--high)] font-bold">62/100</span>
              <span className="text-[var(--text-muted)]"> — </span>
              <span className="text-[var(--high)]">Needs Attention</span>
            </div>
          </div>
        </div>

        {/* Features grid */}
        <div className="mt-24 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {[
            {
              icon: (
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              ),
              title: "13+ Security Tests",
              desc: "Headers, SSL, XSS, SQLi, CORS, ports, cookies, and more — run all at once or pick your level.",
            },
            {
              icon: (
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              ),
              title: "Results in Seconds",
              desc: "Quick scan completes in 30 seconds. No setup, no agents — just enter a URL and go.",
            },
            {
              icon: (
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              ),
              title: "Detailed Reports",
              desc: "Every finding includes severity, evidence, CVSS score, and step-by-step remediation guidance.",
            },
          ].map((feature, i) => (
            <div
              key={i}
              className="card-base p-6"
            >
              <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--accent-dim)] text-[var(--accent)]">
                {feature.icon}
              </div>
              <h3 className="mb-2 text-base font-semibold">{feature.title}</h3>
              <p className="text-sm leading-relaxed text-[var(--text-secondary)]">
                {feature.desc}
              </p>
            </div>
          ))}
        </div>

        {/* Scan levels preview */}
        <div className="mt-24 text-center">
          <h2
            className="text-3xl font-bold tracking-tight"
            style={{ fontFamily: "var(--font-jetbrains)" }}
          >
            Three scan levels. One goal.
          </h2>
          <p className="mt-3 text-[var(--text-secondary)]">
            Choose the depth that matches your needs.
          </p>

          <div className="mt-10 grid gap-6 sm:grid-cols-3">
            {[
              {
                name: "Quick",
                time: "~30s",
                modules: "5 modules",
                color: "var(--accent)",
                desc: "Passive checks — headers, SSL, cookies, info disclosure. Zero risk to production.",
              },
              {
                name: "Standard",
                time: "~2min",
                modules: "7 modules",
                color: "var(--medium)",
                desc: "Active testing — adds CORS and XSS detection. Safe payloads only.",
                featured: true,
              },
              {
                name: "Deep",
                time: "~10min",
                modules: "13 modules",
                color: "var(--critical)",
                desc: "Full pentest simulation — port scanning, advanced XSS, fuzzing, and more.",
              },
            ].map((level, i) => (
              <div
                key={i}
                className={`card-base relative p-6 text-left ${
                  level.featured ? "glow-border" : ""
                }`}
              >
                {level.featured && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-[var(--accent)] px-3 py-0.5 text-xs font-medium text-black">
                    Recommended
                  </div>
                )}
                <div
                  className="mb-3 text-xs font-semibold uppercase tracking-widest"
                  style={{ color: level.color, fontFamily: "var(--font-jetbrains)" }}
                >
                  {level.name}
                </div>
                <div className="mb-1 text-2xl font-bold">{level.time}</div>
                <div className="mb-3 text-xs text-[var(--text-muted)]">
                  {level.modules}
                </div>
                <p className="text-sm leading-relaxed text-[var(--text-secondary)]">
                  {level.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-[var(--border)] py-8">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6">
          <span className="text-sm text-[var(--text-muted)]">
            SecureScan — Automated Security Audits
          </span>
          <span className="text-xs text-[var(--text-muted)] font-[family-name:var(--font-jetbrains)]">
            v0.1.0
          </span>
        </div>
      </footer>
    </div>
  );
}
