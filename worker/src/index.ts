import { Worker } from "bullmq";
import { runScan } from "./engine";
import type { ScanJobData } from "../../src/lib/queue";

// ---------------------------------------------------------------------------
// Redis connection configuration
// ---------------------------------------------------------------------------

const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

function parseRedisUrl(url: string) {
  const parsed = new URL(url);
  return {
    host: parsed.hostname || "localhost",
    port: parseInt(parsed.port || "6379"),
    password: parsed.password || undefined,
  };
}

const connection = parseRedisUrl(REDIS_URL);

// ---------------------------------------------------------------------------
// Worker setup
// ---------------------------------------------------------------------------

const QUEUE_NAME = "scan-queue";

console.log(`[Worker] Starting scan worker...`);
console.log(`[Worker] Redis: ${connection.host}:${connection.port}`);

const scanWorker = new Worker<ScanJobData>(
  QUEUE_NAME,
  async (job) => {
    console.log(
      `[Worker] Processing job ${job.id}: scanId=${job.data.scanId}, targetUrl=${job.data.targetUrl}, scanLevel=${job.data.scanLevel}`
    );

    await runScan({ data: job.data });

    return {
      scanId: job.data.scanId,
      targetUrl: job.data.targetUrl,
      scanLevel: job.data.scanLevel,
      completedAt: new Date().toISOString(),
    };
  },
  {
    connection,
    concurrency: 1, // Process one scan at a time to avoid overwhelming targets
    limiter: {
      max: 1,
      duration: 5000, // Minimum 5 seconds between jobs
    },
  }
);

// ---------------------------------------------------------------------------
// Worker event handlers
// ---------------------------------------------------------------------------

scanWorker.on("completed", (job) => {
  console.log(`[Worker] Job ${job.id} completed successfully (scanId: ${job.data.scanId})`);
});

scanWorker.on("failed", (job, err) => {
  if (job) {
    console.error(
      `[Worker] Job ${job.id} failed (scanId: ${job.data.scanId}): ${err.message}`
    );
  } else {
    console.error(`[Worker] Job failed: ${err.message}`);
  }
});

scanWorker.on("error", (err) => {
  console.error(`[Worker] Worker error: ${err.message}`);
});

scanWorker.on("stalled", (jobId) => {
  console.warn(`[Worker] Job ${jobId} stalled`);
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

async function shutdown(signal: string) {
  console.log(`[Worker] Received ${signal}. Shutting down gracefully...`);
  try {
    await scanWorker.close();
    console.log("[Worker] Worker closed successfully.");
    process.exit(0);
  } catch (err) {
    console.error("[Worker] Error during shutdown:", err);
    process.exit(1);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// Prevent the process from exiting immediately
process.on("unhandledRejection", (reason) => {
  console.error("[Worker] Unhandled promise rejection:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("[Worker] Uncaught exception:", err);
  // Don't exit — let the worker try to recover
});

console.log(`[Worker] Scan worker is ready. Listening on queue "${QUEUE_NAME}".`);
