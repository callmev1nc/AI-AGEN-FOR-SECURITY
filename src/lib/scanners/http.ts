/**
 * Shared, SSRF-safe HTTP helper for every scanner.
 *
 * All scanner network egress MUST go through this module, which delegates to
 * src/lib/safe-fetch.ts. That guard enforces:
 *   - http(s)-only protocol
 *   - target resolves to a public IP (blocks loopback, RFC1918, link-local
 *     incl. cloud metadata 169.254.169.254, multicast, reserved ranges)
 *   - DNS-rebinding protection (connect pinned to the validated IP)
 *   - per-redirect re-validation of the new host
 *   - timeouts + response body cap
 *
 * This replaces the per-scanner raw `http`/`https` helpers that previously
 * connected straight to `parsed.hostname` with no checks.
 *
 * Behaviour contract for scanners:
 *   - On any SafeFetchError (SSRF block, timeout, DNS failure) or network
 *     error, resolves to `null` — matching the previous `resolve(null)`
 *     helpers, so a single unreachable/blocked target degrades a scanner
 *     gracefully (scan-runner also try/catch-wraps every module).
 *   - `headers` is a lowercased `Record<string,string>` (array values joined
 *     except Set-Cookie, which is returned separately in `setCookie`).
 *   - Pass `followRedirects: false` for fuzzing/preflight/sensitive-path
 *     probes that must inspect the raw first response.
 */
import { safeFetch, SafeFetchError } from "@/lib/safe-fetch";

export interface ScannerResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  /** Raw Set-Cookie values, one entry per cookie (empty if none). */
  setCookie: string[];
}

export interface ScannerRequestOptions {
  /** Any HTTP method (GET/POST/OPTIONS/PROPFIND/...). Default "GET". */
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  /** Default true. Set false for fuzzing/preflight/probing. */
  followRedirects?: boolean;
  maxRedirects?: number;
  maxBodyBytes?: number;
  /** Re-throw SafeFetchError instead of resolving to null. Default false. */
  throwOnBlock?: boolean;
}

/**
 * Core SSRF-safe request. Returns null on block/timeout/network error unless
 * `throwOnBlock` is set.
 */
export async function scannerRequest(
  url: string,
  opts: ScannerRequestOptions = {}
): Promise<ScannerResponse | null> {
  try {
    const res = await safeFetch(url, {
      method: opts.method ?? "GET",
      headers: opts.headers,
      body: opts.body,
      timeoutMs: opts.timeoutMs,
      followRedirects: opts.followRedirects ?? true,
      maxRedirects: opts.maxRedirects,
      maxBodyBytes: opts.maxBodyBytes,
    });
    const body = await res.text();
    return {
      statusCode: res.status,
      headers: res.headers,
      body,
      setCookie: res.setCookie,
    };
  } catch (err) {
    if (opts.throwOnBlock && err instanceof SafeFetchError) throw err;
    return null;
  }
}

/**
 * SSRF-safe GET returning just `{ statusCode, body }`. Convenience for the
 * many scanners (xss, sqli, prompt-injection, ...) that only need the body.
 * Does not follow redirects (preserves original reflection-probe behaviour).
 */
export async function fetchBody(
  url: string,
  opts: Omit<ScannerRequestOptions, "method" | "body"> = {}
): Promise<{ statusCode: number; body: string } | null> {
  const res = await scannerRequest(url, {
    ...opts,
    method: "GET",
    followRedirects: opts.followRedirects ?? false,
  });
  if (!res) return null;
  return { statusCode: res.statusCode, body: res.body };
}

/**
 * SSRF-safe GET returning the full response (status + headers + body + cookies).
 */
export async function fetchFull(
  url: string,
  opts: Omit<ScannerRequestOptions, "method" | "body"> = {}
): Promise<ScannerResponse | null> {
  return scannerRequest(url, { ...opts, method: "GET" });
}
