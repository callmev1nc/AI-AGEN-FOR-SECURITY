/**
 * safe-fetch.ts — SSRF-safe outbound HTTP for every scanner.
 *
 * All scanner network egress MUST go through `safeFetch` (HTTP scanners) or
 * `resolveAndAssertPublic` (raw-socket scanners like ssl/ports). The guard:
 *   1. Allows only http/https protocols.
 *   2. Resolves the hostname via node:dns and rejects if ANY resolved address
 *      is private/loopback/link-local/multicast/etc. (blocks cloud metadata
 *      endpoints such as 169.254.169.254 and RFC1918 ranges).
 *   3. Connects through a custom `lookup` that returns the *already-validated*
 *      IP, defeating DNS-rebinding (the address cannot change between the
 *      check and the connect).
 *   4. Re-runs the full resolve+assert cycle on every redirect hop and rejects
 *      protocol switches away from http/https.
 *
 * An allowlist (`SAFE_FETCH_ALLOWLIST`) is supported as a "future internal
 * scanning mode" hook; by default it is empty = strict public-internet-only.
 */
import * as http from "http";
import * as https from "https";
import { lookup as dnsLookup } from "node:dns/promises";
import type { LookupAddress, LookupOptions } from "node:dns";
import type { LookupFunction } from "net";
import { logger } from "@/lib/logger";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type SafeFetchErrorCode =
  | "BLOCKED_PRIVATE_IP"
  | "BLOCKED_PROTOCOL"
  | "BLOCKED_HOSTNAME"
  | "TOO_MANY_REDIRECTS"
  | "TIMEOUT"
  | "DNS_FAILED"
  | "HTTP_ERROR"
  | "BODY_TOO_LARGE";

export class SafeFetchError extends Error {
  constructor(public code: SafeFetchErrorCode, message: string) {
    super(message);
    this.name = "SafeFetchError";
  }
}

// ---------------------------------------------------------------------------
// IP / CIDR parsing (no external dependency)
// ---------------------------------------------------------------------------

interface Ipv4 {
  family: 4;
  value: number; // uint32
}

interface Ipv6 {
  family: 6;
  hi: bigint; // top 64 bits
  lo: bigint; // bottom 64 bits
}

function parseIpv4(str: string): Ipv4 | null {
  const parts = str.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8) | octet;
  }
  // force unsigned 32-bit
  value = value >>> 0;
  return { family: 4, value };
}

/** Expand an IPv6 string (with :: shorthand) into 8 hextets. Returns null if invalid. */
function parseIpv6(str: string): Ipv6 | null {
  const clean = str.trim();
  // Disallow embedded IPv4 dotted-quad shorthand for simplicity but still support it:
  let address = clean;
  // Handle "::" expansion.
  const halves = address.split("::");
  if (halves.length > 2) return null; // only one :: allowed

  // Replace a trailing/leading dotted-quad in the last group.
  const expandQuad = (group: string): string[] | null => {
    const groups = group.split(":").filter((g) => g !== "");
    const out: string[] = [];
    for (let i = 0; i < groups.length; i++) {
      if (i === groups.length - 1 && groups[i].includes(".")) {
        const v4 = parseIpv4(groups[i]);
        if (!v4) return null;
        out.push(((v4.value >> 16) & 0xffff).toString(16));
        out.push((v4.value & 0xffff).toString(16));
      } else {
        out.push(groups[i]);
      }
    }
    return out;
  };

  let head: string[] = [];
  let tail: string[] = [];
  if (halves.length === 2) {
    const h = expandQuad(halves[0]);
    const t = expandQuad(halves[1]);
    if (h === null || t === null) return null;
    head = h;
    tail = t;
    const missing = 8 - (head.length + tail.length);
    if (missing < 0) return null;
    const middle = Array.from({ length: missing }, () => "0");
    const all = [...head, ...middle, ...tail];
    return hextetsToIpv6(all);
  } else {
    const all = expandQuad(halves[0]);
    if (all === null || all.length !== 8) return null;
    return hextetsToIpv6(all);
  }
}

function hextetsToIpv6(hextets: string[]): Ipv6 | null {
  if (hextets.length !== 8) return null;
  let hi = 0n;
  let lo = 0n;
  for (let i = 0; i < 8; i++) {
    const h = hextets[i];
    if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
    const val = BigInt(parseInt(h, 16));
    if (i < 4) {
      hi |= val << BigInt((3 - i) * 16);
    } else {
      lo |= val << BigInt((7 - i) * 16);
    }
  }
  return { family: 6, hi, lo };
}

/** Is this string a parseable IP literal (v4 or v6)? */
export function isIpLiteral(str: string): boolean {
  return parseIpv4(str) !== null || parseIpv6(str) !== null;
}

function ipFamily(ip: string): 4 | 6 {
  return ip.includes(":") ? 6 : 4;
}

function stripBrackets(host: string): string {
  if (host.startsWith("[") && host.endsWith("]")) return host.slice(1, -1);
  return host;
}

// IPv4 private/reserved ranges (as [base, mask] uint32 pairs).
//  - 0.0.0.0/8       "this network"
//  - 10.0.0.0/8      private
//  - 100.64.0.0/10   CGNAT
//  - 127.0.0.0/8     loopback
//  - 169.254.0.0/16  link-local (incl. cloud metadata 169.254.169.254)
//  - 172.16.0.0/12   private
//  - 192.0.0.0/24    IETF protocol assignments
//  - 192.168.0.0/16  private
//  - 198.18.0.0/15   benchmarking
//  - 224.0.0.0/4     multicast
//  - 240.0.0.0/4     reserved (future)
const IPV4_BLOCKED: Array<[number, number]> = [
  [0x00000000, 0xff000000],
  [0x0a000000, 0xff000000],
  [0x64400000, 0xffc00000],
  [0x7f000000, 0xff000000],
  [0xa9fe0000, 0xffff0000],
  [0xac100000, 0xfff00000],
  [0xc0000000, 0xffffff00],
  [0xc0a80000, 0xffff0000],
  [0xc6120000, 0xfffe0000],
  [0xe0000000, 0xf0000000],
  [0xf0000000, 0xf0000000],
];

function isPrivateIpv4(value: number): boolean {
  for (const [base, mask] of IPV4_BLOCKED) {
    if ((value & mask) >>> 0 === base) return true;
  }
  return false;
}

// IPv6 blocked ranges. `baseHi` holds the top 64 bits (hextets 0-3) where
// hextet[0] occupies bits 48-63, hextet[1] bits 32-47, etc. So a first-hextet
// value V must be shifted << 48, and a first-two-hextets value << 32. (Earlier
// these were mis-shifted, so ULA/link-local/multicast never matched.)
interface Ipv6Cidr {
  baseHi: bigint;
  baseLo: bigint;
  prefix: number;
}
const IPV6_BLOCKED: Ipv6Cidr[] = [
  { baseHi: 0n, baseLo: 0n, prefix: 128 }, // ::        unspecified
  { baseHi: 0n, baseLo: 1n, prefix: 128 }, // ::1       loopback
  // ::ffff:0:0/96 (v4-mapped) is intentionally NOT here: the special branch
  // below decodes the embedded IPv4 and re-checks it, so public v4-mapped
  // addresses (e.g. ::ffff:8.8.8.8) are allowed while private ones are blocked.
  { baseHi: 0x0064ff9bn << 32n, baseLo: 0n, prefix: 96 }, // 64:ff9b:: NAT64
  { baseHi: 0x100n << 48n, baseLo: 0n, prefix: 64 }, // 100::/64 discard prefix
  { baseHi: 0xfc00n << 48n, baseLo: 0n, prefix: 7 }, // fc00::/7  ULA
  { baseHi: 0xfe80n << 48n, baseLo: 0n, prefix: 10 }, // fe80::/10 link-local
  { baseHi: 0xff00n << 48n, baseLo: 0n, prefix: 8 }, // ff00::/8  multicast
  { baseHi: 0x20010db8n << 32n, baseLo: 0n, prefix: 32 }, // 2001:db8::/32 documentation
];

function mask128(prefix: number): { hi: bigint; lo: bigint } {
  if (prefix >= 128) return { hi: 0xffffffffffffffffn, lo: 0xffffffffffffffffn };
  if (prefix <= 64) {
    const shift = BigInt(64 - prefix);
    const hi = (0xffffffffffffffffn << shift) & 0xffffffffffffffffn;
    return { hi, lo: 0n };
  }
  const shift = BigInt(128 - prefix);
  const lo = (0xffffffffffffffffn << shift) & 0xffffffffffffffffn;
  return { hi: 0xffffffffffffffffn, lo };
}

function isPrivateIpv6(ip: Ipv6): boolean {
  // v4-mapped (::ffff:a.b.c.d): decode the embedded IPv4 and re-check it.
  const mapped = 0xffff00000000n;
  if (ip.hi === 0n && (ip.lo & 0xffff000000000000n) === 0n && (ip.lo & mapped) === mapped) {
    const v4 = Number(ip.lo & 0xffffffffn) >>> 0;
    if (isPrivateIpv4(v4)) return true;
  }
  for (const cidr of IPV6_BLOCKED) {
    const { hi, lo } = mask128(cidr.prefix);
    if ((ip.hi & hi) === cidr.baseHi && (ip.lo & lo) === (cidr.baseLo & lo)) {
      // exact-match checks (prefix 128) must compare full value
      if (cidr.prefix >= 128) {
        if (ip.hi === cidr.baseHi && ip.lo === cidr.baseLo) return true;
        continue;
      }
      return true;
    }
  }
  return false;
}

/**
 * Returns true if the given IP literal (v4 or v6, incl. v4-mapped IPv6) is a
 * private/internal/non-routable address that must not be scanned.
 */
export function isPrivateIp(ip: string): boolean {
  const clean = stripBrackets(ip.trim());
  const v4 = parseIpv4(clean);
  if (v4) return isPrivateIpv4(v4.value);
  const v6 = parseIpv6(clean);
  if (v6) return isPrivateIpv6(v6);
  // Not an IP literal — treat as "not private" (hostname handling is separate).
  return false;
}

// ---------------------------------------------------------------------------
// Allowlist (future internal-scanning mode)
// ---------------------------------------------------------------------------

interface Allowlist {
  hosts: Set<string>;
  cidrs: Array<{ raw: string; v4?: Ipv4; v6?: Ipv6; prefix: number }>;
}

function parseAllowlist(): Allowlist {
  const raw = process.env.SAFE_FETCH_ALLOWLIST;
  const out: Allowlist = { hosts: new Set(), cidrs: [] };
  if (!raw) return out;
  for (let part of raw.split(",")) {
    part = part.trim();
    if (!part) continue;
    if (part.includes("/")) {
      const [addr, prefixStr] = part.split("/");
      const prefix = Number(prefixStr);
      const v4 = parseIpv4(addr);
      const v6 = v4 ? null : parseIpv6(addr);
      out.cidrs.push({ raw: part, v4: v4 ?? undefined, v6: v6 ?? undefined, prefix });
    } else {
      out.hosts.add(part.toLowerCase());
    }
  }
  return out;
}

function hostnameMatchesAllowlist(hostname: string, allow: Allowlist): boolean {
  const h = hostname.toLowerCase();
  for (const allowed of allow.hosts) {
    if (h === allowed || h.endsWith("." + allowed)) return true;
  }
  return false;
}

function ipMatchesAllowlist(ips: string[], allow: Allowlist): boolean {
  for (const cidr of allow.cidrs) {
    for (const ip of ips) {
      const v4 = parseIpv4(ip);
      if (v4 && cidr.v4 && cidr.prefix >= 0 && cidr.prefix <= 32) {
        const { value } = v4;
        const shift = 32 - cidr.prefix;
        const mask = shift >= 32 ? 0 : (0xffffffff << shift) >>> 0;
        if ((value & mask) >>> 0 === (cidr.v4.value & mask) >>> 0) return true;
      }
      const v6 = parseIpv6(ip);
      if (v6 && cidr.v6 && cidr.prefix >= 0 && cidr.prefix <= 128) {
        const { hi, lo } = mask128(cidr.prefix);
        if ((v6.hi & hi) === cidr.v6.hi && (v6.lo & lo) === (cidr.v6.lo & lo)) return true;
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Hostname guards
// ---------------------------------------------------------------------------

const BLOCKED_HOSTNAME_SUFFIXES = [".localhost", ".local", ".internal", ".home", ".lan", ".intranet"];

function assertHostnameAllowed(hostname: string): void {
  const h = hostname.toLowerCase();
  if (h === "localhost" || BLOCKED_HOSTNAME_SUFFIXES.some((s) => h === s.slice(1) || h.endsWith(s))) {
    throw new SafeFetchError("BLOCKED_HOSTNAME", `Hostname "${hostname}" is a local/internal name`);
  }
}

/**
 * Resolve a hostname (or validate an IP literal) and assert every resolved
 * address is public-routable. Returns the validated addresses. Throws
 * SafeFetchError on any disallowed target. Reused by raw-socket scanners
 * (ssl/ports) that cannot go through safeFetch.
 */
export async function resolveAndAssertPublic(hostname: string): Promise<string[]> {
  const clean = stripBrackets(hostname.trim());
  const allow = parseAllowlist();

  // IP literal: validate directly (no DNS).
  const v4 = parseIpv4(clean);
  const v6 = v4 ? null : parseIpv6(clean);
  if (v4 || v6) {
    const ip = v4 ? clean : clean;
    if (isPrivateIp(ip)) {
      // allowlist bypass for explicit internal-scanning mode
      if (ipMatchesAllowlist([ip], allow)) return [ip];
      throw new SafeFetchError("BLOCKED_PRIVATE_IP", `Target IP ${ip} is private/internal`);
    }
    return [ip];
  }

  // Hostname-level defense.
  if (!hostnameMatchesAllowlist(clean, allow)) {
    assertHostnameAllowed(clean);
  }

  let records: LookupAddress[];
  try {
    records = await dnsLookup(clean, { all: true, verbatim: true });
  } catch (e) {
    throw new SafeFetchError("DNS_FAILED", `DNS resolution failed for ${clean}: ${(e as Error).message}`);
  }

  if (!records.length) {
    throw new SafeFetchError("DNS_FAILED", `No DNS records found for ${clean}`);
  }

  const addresses = records.map((r) => r.address);
  for (const address of addresses) {
    if (isPrivateIp(address) && !ipMatchesAllowlist(addresses, allow)) {
      throw new SafeFetchError(
        "BLOCKED_PRIVATE_IP",
        `${clean} resolves to private/internal address ${address}`
      );
    }
  }
  return addresses;
}

// ---------------------------------------------------------------------------
// safeFetch
// ---------------------------------------------------------------------------

export interface SafeFetchOptions {
  // Any HTTP method string (scanners send OPTIONS/PROPFIND/etc., not just the
  // safe verbs). doRequest passes it straight to node's http.request.
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeoutMs?: number;
  maxRedirects?: number;
  followRedirects?: boolean;
  signal?: AbortSignal; // composed with the internal timeout
  maxBodyBytes?: number;
}

export interface SafeFetchResponse {
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  /** Raw Set-Cookie header values, one per cookie (never comma-joined). */
  setCookie: string[];
  buffer(): Promise<Buffer>;
  text(): Promise<string>;
  json(): Promise<unknown>;
}

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024;
export const SCANNER_USER_AGENT = "SecureScan/1.0 (+https://securescan.app)";

function normalizeHeaders(raw: http.IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  return out;
}

interface RequestResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  // Raw Set-Cookie values, one entry per cookie. Kept separate from `headers`
  // because Set-Cookie must not be comma-joined (Expires dates contain commas
  // and each cookie is a distinct header).
  setCookie: string[];
  body: Buffer;
  location?: string;
}

function doRequest(
  parsed: URL,
  validatedIp: string,
  opts: SafeFetchOptions,
  timeoutSignal: AbortSignal
): Promise<RequestResult> {
  return new Promise((resolve, reject) => {
    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;
    const defaultPort = isHttps ? 443 : 80;
    const port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;
    const path = parsed.pathname + parsed.search;

    // Custom lookup pins the connection to the already-validated IP so the
    // resolver can't return a different (private) address between check & connect.
    const lookup: LookupFunction = (_h: string, options: LookupOptions | ((err: NodeJS.ErrnoException | null, address: string, family: number) => void), cb?: (err: NodeJS.ErrnoException | null, address: string, family: number) => void) => {
      const callback = typeof options === "function" ? options : cb!;
      callback(null, validatedIp, ipFamily(validatedIp));
    };

    const reqHeaders: Record<string, string> = {
      "User-Agent": SCANNER_USER_AGENT,
      Accept: "*/*",
      ...opts.headers,
    };

    const reqOptions: https.RequestOptions = {
      method: opts.method || "GET",
      hostname: parsed.hostname, // keep original host for Host header / SNI
      port,
      path,
      headers: reqHeaders,
      lookup,
      servername: isHttps ? parsed.hostname : undefined, // SNI
      // Scanners must reach targets with invalid/expired/self-signed certs
      // (that's exactly what ssl.ts reports). The SSRF guard runs before
      // connect, so disabling cert rejection does not weaken it.
      rejectUnauthorized: false,
      signal: timeoutSignal,
    };

    const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

    const req = lib.request(reqOptions, (res) => {
      const chunks: Buffer[] = [];
      let len = 0;
      res.on("data", (chunk: Buffer) => {
        len += chunk.length;
        if (len > maxBodyBytes) {
          req.destroy();
          reject(new SafeFetchError("BODY_TOO_LARGE", `Response body exceeded ${maxBodyBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        resolve({
          status: res.statusCode ?? 0,
          statusText: res.statusMessage ?? "",
          headers: normalizeHeaders(res.headers),
          setCookie: Array.isArray(res.headers["set-cookie"])
            ? [...(res.headers["set-cookie"] as string[])]
            : [],
          body: Buffer.concat(chunks),
          location: res.headers.location ? String(res.headers.location) : undefined,
        });
      });
      res.on("error", (err) => reject(err));
    });

    req.on("abort", () => {
      reject(new SafeFetchError("TIMEOUT", `Request to ${parsed.toString()} aborted`));
    });
    req.on("error", (err) => {
      if (timeoutSignal.aborted) {
        reject(new SafeFetchError("TIMEOUT", `Request to ${parsed.toString()} timed out`));
      } else {
        reject(err);
      }
    });

    if (opts.body !== undefined) {
      req.write(opts.body);
    }
    req.end();
  });
}

async function safeFetchInternal(
  url: string,
  opts: SafeFetchOptions,
  redirectCount: number,
  timeoutSignal: AbortSignal
): Promise<SafeFetchResponse> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SafeFetchError("HTTP_ERROR", `Invalid URL: ${url}`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SafeFetchError("BLOCKED_PROTOCOL", `Protocol "${parsed.protocol}" is not allowed (http/https only)`);
  }

  const addresses = await resolveAndAssertPublic(parsed.hostname);
  const validatedIp = addresses[0];

  const result = await doRequest(parsed, validatedIp, opts, timeoutSignal);

  const isRedirect = [301, 302, 303, 307, 308].includes(result.status);
  if (isRedirect && opts.followRedirects !== false && result.location) {
    if (redirectCount >= (opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS)) {
      throw new SafeFetchError("TOO_MANY_REDIRECTS", `Too many redirects from ${url}`);
    }
    const nextUrl = new URL(result.location, parsed).toString();
    logger.info("SafeFetch", `Following redirect ${redirectCount + 1}: ${url} -> ${nextUrl}`);
    return safeFetchInternal(nextUrl, opts, redirectCount + 1, timeoutSignal);
  }

  return {
    url: parsed.toString(),
    status: result.status,
    statusText: result.statusText,
    headers: result.headers,
    setCookie: result.setCookie,
    buffer: async () => result.body,
    text: async () => result.body.toString("utf8"),
    json: async () => JSON.parse(result.body.toString("utf8")),
  };
}

/**
 * SSRF-safe HTTP request. Throws SafeFetchError on blocked targets, timeouts,
 * protocol violations, or too many redirects. Returns a SafeFetchResponse.
 */
export async function safeFetch(url: string, options: SafeFetchOptions = {}): Promise<SafeFetchResponse> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  // Compose with an externally-provided signal (e.g. scan budget).
  const external = options.signal;
  const onExternalAbort = () => controller.abort();
  if (external) {
    if (external.aborted) controller.abort();
    else external.addEventListener("abort", onExternalAbort, { once: true });
  }

  try {
    return await safeFetchInternal(url, options, 0, controller.signal);
  } finally {
    clearTimeout(timer);
    if (external) external.removeEventListener("abort", onExternalAbort);
  }
}
