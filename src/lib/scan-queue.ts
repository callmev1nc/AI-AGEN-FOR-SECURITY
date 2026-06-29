/**
 * scan-queue.ts — BullMQ queue for deep scans.
 *
 * Deep scans are enqueued when SCAN_QUEUE_ENABLED=1. The worker runs on a
 * separate host (Fly.io / Railway / VPS) that supports persistent processes.
 */
import { Queue, Worker } from "bullmq";
import { logger } from "@/lib/logger";
import { runScanInline } from "@/lib/scan-runner";
import { createAdminClient } from "@/lib/supabase/admin";

const REDIS_URL = process.env.REDIS_URL || "";
const isEnabled = process.env.SCAN_QUEUE_ENABLED === "1";

let scanQueue: Queue | null = null;

function getConnection() {
  return { url: REDIS_URL };
}

export function getScanQueue(): Queue {
  if (!scanQueue) {
    scanQueue = new Queue("scans", { connection: getConnection() });
  }
  return scanQueue;
}

export async function enqueueScan(params: {
  scanId: string;
  targetUrl: string;
  scanLevel: "quick" | "standard" | "deep";
  scanType?: "website" | "api" | "infrastructure";
}): Promise<void> {
  if (!isEnabled || !REDIS_URL) {
    // Fallback: run inline
    await runScanInline(params);
    return;
  }

  const queue = getScanQueue();
  await queue.add("scan", params, {
    attempts: 3,
    backoff: { type: "exponential", delay: 5000 },
  });
  logger.info("ScanQueue", `Enqueued scan ${params.scanId} for ${params.targetUrl}`);
}

export function createScanWorker(): Worker {
  // Periodically reclaim scans orphaned by a worker crash / forced redeploy so
  // they don't stay stuck in "running" forever.
  setInterval(() => {
    void reclaimStaleScans();
  }, 60_000);

  const worker = new Worker(
    "scans",
    async (job) => {
      const { scanId, targetUrl, scanLevel, scanType } = job.data;
      logger.info("ScanQueueWorker", `Processing scan ${scanId} (attempt ${job.attemptsMade + 1})`);
      await runScanInline({ scanId, targetUrl, scanLevel, scanType });
    },
    {
      connection: getConnection(),
      concurrency: Number(process.env.WORKER_CONCURRENCY) || 2,
    }
  );

  worker.on("completed", (job) => {
    logger.info("ScanQueueWorker", `Scan ${job.data.scanId} completed`);
  });

  worker.on("failed", (job, err) => {
    logger.error("ScanQueueWorker", `Scan ${job?.data.scanId} failed: ${err.message}`);
  });

  return worker;
}

export { isEnabled };

// ---------------------------------------------------------------------------
// Crash recovery: reclaim scans stuck in "running" after a worker crash.
// ---------------------------------------------------------------------------

export interface StaleScanRow {
  id: string;
  status: string;
  heartbeatAt: string | null;
  startedAt: string | null;
}

/**
 * Pure predicate (unit-tested): is this scan "running" with a heartbeat (or
 * fallback startedAt) older than staleMs?
 */
export function isScanStale(scan: StaleScanRow, now: number, staleMs: number): boolean {
  if (scan.status !== "running") return false;
  const ts = scan.heartbeatAt ?? scan.startedAt;
  if (!ts) return false; // nothing to judge by — leave it alone
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return false;
  return t + staleMs < now;
}

/**
 * Mark any "running" scan whose heartbeat is older than staleMs as "failed".
 * Intended to run periodically from the worker process.
 */
export async function reclaimStaleScans(staleMs = 5 * 60 * 1000): Promise<number> {
  const admin = createAdminClient();
  const { data, error } = await admin
    .from("scans")
    .select("id, status, heartbeatAt, startedAt")
    .eq("status", "running");
  if (error || !data) return 0;

  const now = Date.now();
  const stale = (data as StaleScanRow[]).filter((s) => isScanStale(s, now, staleMs));
  for (const s of stale) {
    await admin
      .from("scans")
      .update({
        status: "failed",
        errorMessage:
          "Reclaimed: scan heartbeat exceeded the staleness threshold (worker likely crashed).",
      })
      .eq("id", s.id);
  }
  if (stale.length > 0) {
    logger.info("ScanQueue", `Reclaimed ${stale.length} stale scan(s)`);
  }
  return stale.length;
}
