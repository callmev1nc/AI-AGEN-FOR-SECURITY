"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { trpcClient } from "@/lib/trpc-client";

type Scan = {
  id: string;
  targetUrl: string;
  status: string;
  scanLevel: string;
  overallScore: number | null;
  createdAt: string;
};

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  useEffect(() => {
    trpcClient.scan.list.query({ limit: 10 }).then((data) => {
      setScans(data.items as Scan[]);
      setNextCursor(data.nextCursor);
      setLoading(false);
    }).catch((err) => {
      setError(err instanceof Error ? err.message : "Failed to load scans");
      setLoading(false);
    });
  }, []);

  async function loadMore() {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    try {
      const data = await trpcClient.scan.list.query({ limit: 10, cursor: nextCursor });
      setScans((prev) => [...prev, ...(data.items as Scan[])]);
      setNextCursor(data.nextCursor);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load more");
    } finally {
      setLoadingMore(false);
    }
  }

  const totalScans = scans.length;
  const completedScans = scans.filter((s) => s.status === "completed");
  const avgScore =
    completedScans.length > 0
      ? Math.round(
          completedScans.reduce((sum, s) => sum + (s.overallScore ?? 0), 0) /
            completedScans.length
        )
      : null;
  const atRiskScans = completedScans.filter((s) => (s.overallScore ?? 100) < 50).length;
  const lastScan = scans.length > 0 ? scans[0] : null;

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

      {error && (
        <div className="rounded-lg border border-[#ef4444]/30 bg-[#ef4444]/10 px-4 py-3 text-sm text-[#ef4444]">
          {error}
          <button onClick={() => setError("")} className="ml-3 text-xs underline hover:no-underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Stats cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            label: "Total Scans",
            value: loading ? "..." : String(totalScans),
            icon: (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            ),
          },
          {
            label: "Avg. Score",
            value: loading ? "..." : avgScore !== null ? String(avgScore) : "—",
            icon: (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            ),
          },
          {
            label: "At-Risk Scans",
            value: loading ? "..." : String(atRiskScans),
            icon: (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            ),
            color: "text-[var(--critical)]",
          },
          {
            label: "Last Scan",
            value: loading
              ? "..."
              : lastScan
              ? new Date(lastScan.createdAt).toLocaleDateString()
              : "Never",
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
        {scans.length === 0 ? (
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
        ) : (
          <div className="card-base overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">URL</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Level</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Score</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">Date</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} className="border-b border-[var(--border)] last:border-0 hover:bg-[var(--bg-card-hover)] transition-colors">
                    <td className="px-4 py-3">
                      <Link href={`/dashboard/scans/${scan.id}`} className="text-[var(--accent)] hover:underline">
                        {scan.targetUrl}
                      </Link>
                    </td>
                    <td className="px-4 py-3 uppercase text-xs" style={{ fontFamily: "var(--font-jetbrains)" }}>
                      {scan.scanLevel}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-4 py-3 font-semibold" style={{ fontFamily: "var(--font-jetbrains)" }}>
                      {scan.overallScore ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-[var(--text-muted)]">
                      {new Date(scan.createdAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {nextCursor && (
              <div className="flex justify-center border-t border-[var(--border)] px-4 py-3">
                <button
                  onClick={loadMore}
                  disabled={loadingMore}
                  className="rounded-lg bg-[var(--bg-card-hover)] px-4 py-2 text-xs font-semibold text-[var(--text-secondary)] transition-all hover:brightness-110 disabled:opacity-50"
                >
                  {loadingMore ? "Loading..." : "Load More"}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    queued: "bg-[var(--info-dim)] text-[var(--info)]",
    running: "bg-[var(--medium-dim)] text-[var(--medium)]",
    completed: "bg-[var(--accent-dim)] text-[var(--accent)]",
    failed: "bg-[var(--critical-dim)] text-[var(--critical)]",
  };
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${styles[status] || styles.queued}`}
      style={{ fontFamily: "var(--font-jetbrains)" }}
    >
      {status}
    </span>
  );
}
