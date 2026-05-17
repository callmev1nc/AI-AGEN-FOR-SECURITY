import { Queue } from "bullmq";

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

export const scanQueue = new Queue("scan-queue", { connection });

export interface ScanJobData {
  scanId: string;
  targetUrl: string;
  scanLevel: "quick" | "standard" | "deep";
}
