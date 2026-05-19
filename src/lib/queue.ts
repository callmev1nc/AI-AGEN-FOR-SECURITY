import { Queue } from "bullmq";

function parseRedisUrl(url: string) {
  const parsed = new URL(url);
  return {
    host: parsed.hostname || "localhost",
    port: parseInt(parsed.port || "6379"),
    password: parsed.password || undefined,
  };
}

let queue: Queue | null = null;

export function getScanQueue(): Queue | null {
  const url = process.env.REDIS_URL;
  if (!url) return null;
  if (!queue) {
    queue = new Queue("scan-queue", { connection: parseRedisUrl(url) });
  }
  return queue;
}

export interface ScanJobData {
  scanId: string;
  targetUrl: string;
  scanLevel: "quick" | "standard" | "deep";
}
