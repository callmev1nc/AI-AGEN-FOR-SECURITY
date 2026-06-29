/**
 * worker.ts — Standalone BullMQ worker for deep scans.
 *
 * Runs on a host that supports persistent processes (Fly.io / Railway / Render / VPS).
 * Not deployed to Vercel.
 *
 * Usage:
 *   pnpm tsx worker/worker.ts
 *
 * Env:
 *   REDIS_URL              – BullMQ Redis connection string (TLS)
 *   SCAN_QUEUE_ENABLED     – must be "1"
 *   WORKER_CONCURRENCY     – default 2
 *   NEXT_PUBLIC_SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 */
import { createScanWorker } from "../src/lib/scan-queue";
import { logger } from "../src/lib/logger";

const required = ["REDIS_URL", "NEXT_PUBLIC_SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];
for (const env of required) {
  if (!process.env[env]) {
    console.error(`Missing required env: ${env}`);
    process.exit(1);
  }
}

const worker = createScanWorker();

logger.info("Worker", "Scan worker started. Waiting for jobs...");

// Graceful shutdown
process.on("SIGTERM", async () => {
  logger.info("Worker", "SIGTERM received, shutting down...");
  await worker.close();
  process.exit(0);
});

process.on("SIGINT", async () => {
  logger.info("Worker", "SIGINT received, shutting down...");
  await worker.close();
  process.exit(0);
});
