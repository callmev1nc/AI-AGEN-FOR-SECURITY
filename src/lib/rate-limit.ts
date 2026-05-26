import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const PLAN_LIMITS: Record<string, number> = {
  free: 5,
  pro: 30,
  enterprise: 100,
};

const ratelimiters = new Map<number, Ratelimit>();

function getRatelimit(maxRequests: number): Ratelimit | null {
  const existing = ratelimiters.get(maxRequests);
  if (existing) return existing;

  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) return null;

  const redis = new Redis({ url, token });
  const limiter = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(maxRequests, "1 h"),
    prefix: `securescan:ratelimit:${maxRequests}`,
  });
  ratelimiters.set(maxRequests, limiter);

  return limiter;
}

const inMemoryStore = new Map<string, { count: number; resetAt: number }>();
const WINDOW_MS = 60 * 60 * 1000;

function checkInMemory(identifier: string, maxRequests: number) {
  const now = Date.now();
  const entry = inMemoryStore.get(identifier);

  if (!entry || now > entry.resetAt) {
    inMemoryStore.set(identifier, { count: 1, resetAt: now + WINDOW_MS });
    return { success: true, limit: maxRequests, remaining: maxRequests - 1, reset: now + WINDOW_MS };
  }

  entry.count++;
  const remaining = Math.max(0, maxRequests - entry.count);
  return {
    success: entry.count <= maxRequests,
    limit: maxRequests,
    remaining,
    reset: entry.resetAt,
  };
}

export async function checkRateLimit(
  identifier: string,
  plan?: string
): Promise<{
  success: boolean;
  limit: number;
  remaining: number;
  reset: number;
}> {
  const maxRequests = PLAN_LIMITS[plan || "free"] || 5;
  const limiter = getRatelimit(maxRequests);

  if (!limiter) {
    return checkInMemory(identifier, maxRequests);
  }

  const result = await limiter.limit(identifier);
  return {
    success: result.success,
    limit: maxRequests,
    remaining: result.remaining,
    reset: result.reset,
  };
}
