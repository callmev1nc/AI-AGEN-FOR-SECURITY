import Link from "next/link";

export default function ReportsPage() {
  return (
    <div className="animate-fade-in-up space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1
            className="text-2xl font-bold tracking-tight"
            style={{ fontFamily: "var(--font-jetbrains)" }}
          >
            Reports
          </h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Download and manage your exported security reports.
          </p>
        </div>
      </div>

      <div className="card-base flex items-center justify-center px-6 py-16 text-[var(--text-muted)]">
        <div className="text-center">
          <svg
            className="mx-auto mb-3 h-10 w-10 opacity-40"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1"
          >
            <path d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <p className="text-sm">No reports generated yet</p>
          <p className="mt-1 text-xs">
            Complete a scan and export the results to see reports here.
          </p>
          <Link
            href="/dashboard/scans/new"
            className="mt-4 inline-block rounded-lg bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-black transition-all hover:brightness-110"
          >
            Run a Scan
          </Link>
        </div>
      </div>
    </div>
  );
}
