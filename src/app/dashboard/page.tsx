import Link from "next/link";

export default function DashboardPage() {
  return (
    <div className="animate-fade-in-up space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1
            className="text-2xl font-bold tracking-tight"
            style={{ fontFamily: "var(--font-jetbrains)" }}
          >
            Dashboard
          </h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Overview of your security scans.
          </p>
        </div>
        <Link
          href="/dashboard/scans/new"
          className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110"
        >
          + New Scan
        </Link>
      </div>

      {/* Stats cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            label: "Total Scans",
            value: "0",
            icon: (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            ),
          },
          {
            label: "Avg. Score",
            value: "—",
            icon: (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            ),
          },
          {
            label: "Critical Findings",
            value: "0",
            icon: (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            ),
            color: "text-[var(--critical)]",
          },
          {
            label: "Last Scan",
            value: "Never",
            icon: (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 6v6l4 2" />
              </svg>
            ),
          },
        ].map((stat, i) => (
          <div key={i} className="card-base p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                {stat.label}
              </span>
              <span className={stat.color || "text-[var(--text-secondary)]"}>
                {stat.icon}
              </span>
            </div>
            <div className="mt-3 text-2xl font-bold">{stat.value}</div>
          </div>
        ))}
      </div>

      {/* Recent scans */}
      <div>
        <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Recent Scans
        </h2>
        <div className="card-base overflow-hidden">
          <div className="flex items-center justify-center px-6 py-16 text-[var(--text-muted)]">
            <div className="text-center">
              <svg
                className="mx-auto mb-3 h-10 w-10 opacity-40"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1"
              >
                <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <p className="text-sm">No scans yet</p>
              <p className="mt-1 text-xs">
                Run your first security scan to see results here.
              </p>
              <Link
                href="/dashboard/scans/new"
                className="mt-4 inline-block rounded-lg bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-black transition-all hover:brightness-110"
              >
                Start First Scan
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
