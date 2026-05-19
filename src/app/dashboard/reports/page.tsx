"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { trpcClient } from "@/lib/trpc-client";

interface Report {
  id: string;
  scanId: string;
  format: string;
  storagePath: string;
  createdAt: string;
  scans: { targetUrl: string; overallScore: number | null }[] | null;
}

function scoreColor(score: number | null) {
  if (score === null) return "text-[var(--text-muted)]";
  if (score >= 80) return "text-[var(--accent)]";
  if (score >= 50) return "text-[#f59e0b]";
  return "text-[#ef4444]";
}

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const data = await trpcClient.scan.listReports.query();
        setReports(data as Report[]);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load reports");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  async function handleDownload(reportId: string) {
    setDownloadingId(reportId);
    try {
      const { downloadUrl } = await trpcClient.scan.getReportDownloadUrl.query({
        reportId,
      });
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `report-${reportId}.pdf`;
      a.target = "_blank";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed");
    } finally {
      setDownloadingId(null);
    }
  }

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

      {error && (
        <div className="rounded-lg border border-[#ef4444]/30 bg-[#ef4444]/10 px-4 py-3 text-sm text-[#ef4444]">
          {error}
          <button
            onClick={() => setError("")}
            className="ml-3 text-xs underline hover:no-underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {loading ? (
        <div className="card-base flex items-center justify-center px-6 py-16">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent" />
        </div>
      ) : reports.length === 0 ? (
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
      ) : (
        <div className="card-base overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[var(--border)]">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Score
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Format
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Date
                </th>
                <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Action
                </th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr
                  key={report.id}
                  className="border-b border-[var(--border)] last:border-0 hover:bg-[var(--bg-card-hover)]"
                >
                  <td className="px-4 py-3 text-sm font-medium">
                    {report.scans?.[0]?.targetUrl ?? "—"}
                  </td>
                  <td
                    className={`px-4 py-3 text-sm font-semibold ${scoreColor(report.scans?.[0]?.overallScore ?? null)}`}
                  >
                    {report.scans?.[0]?.overallScore ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-xs uppercase text-[var(--text-secondary)]">
                    {report.format}
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--text-muted)]">
                    {new Date(report.createdAt).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDownload(report.id)}
                      disabled={downloadingId === report.id}
                      className="rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50"
                    >
                      {downloadingId === report.id ? "Loading..." : "Download"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
