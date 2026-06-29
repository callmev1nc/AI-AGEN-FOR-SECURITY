import { AsyncLocalStorage } from "async_hooks";

export interface ScanContext {
  scanId: string;
  level: "quick" | "standard" | "deep";
  type: "website" | "api" | "infrastructure";
  targetUrl: string;
  cache: CacheStore;
}

interface CacheEntry {
  body: string;
  headers: Record<string, string>;
  statusCode: number;
  setCookie: string[];
  ts: number;
}

interface CacheStore {
  get(key: string): CacheEntry | undefined;
  set(key: string, entry: CacheEntry): void;
  clear(): void;
  size(): number;
}

function createLruCache(maxEntries: number): CacheStore {
  const map = new Map<string, CacheEntry>();
  return {
    get(key: string): CacheEntry | undefined {
      const entry = map.get(key);
      if (entry) {
        map.delete(key);
        map.set(key, entry);
      }
      return entry;
    },
    set(key: string, entry: CacheEntry): void {
      if (map.size >= maxEntries) {
        const oldest = map.keys().next();
        if (!oldest.done) map.delete(oldest.value);
      }
      map.set(key, entry);
    },
    clear(): void { map.clear(); },
    size(): number { return map.size; },
  };
}

const scanStorage = new AsyncLocalStorage<ScanContext>();

export function getScanContext(): ScanContext | undefined {
  return scanStorage.getStore();
}

export function runWithContext<T>(ctx: ScanContext, fn: () => Promise<T>): Promise<T> {
  return scanStorage.run(ctx, fn);
}

// Per-target-host semaphore: caps concurrent in-flight requests to a single
// host at maxPerHost. This is the explicit C3 guarantee.
const hostSemaphores = new Map<string, { queue: (() => void)[]; active: number }>();

const MAX_PER_HOST = 3;

export async function acquireHostSlot(hostname: string): Promise<void> {
  const key = hostname.toLowerCase();
  let sem = hostSemaphores.get(key);
  if (!sem) {
    sem = { queue: [], active: 0 };
    hostSemaphores.set(key, sem);
  }
  if (sem.active < MAX_PER_HOST) {
    sem.active++;
    return;
  }
  return new Promise<void>((resolve) => {
    sem!.queue.push(resolve);
  });
}

export function releaseHostSlot(hostname: string): void {
  const key = hostname.toLowerCase();
  const sem = hostSemaphores.get(key);
  if (!sem) return;
  if (sem.queue.length > 0) {
    const next = sem.queue.shift()!;
    next();
  } else {
    sem.active--;
    if (sem.active <= 0 && sem.queue.length === 0) {
      hostSemaphores.delete(key);
    }
  }
}

// Response cache integration

export function initCache(): CacheStore {
  return createLruCache(64);
}

export function cacheGet(key: string): CacheEntry | undefined {
  const ctx = getScanContext();
  if (!ctx) return undefined;
  return ctx.cache.get(key);
}

export function cacheSet(key: string, entry: CacheEntry): void {
  const ctx = getScanContext();
  if (!ctx) return;
  ctx.cache.set(key, entry);
}
