import * as http from "http";
import * as https from "https";
import type { ScannerModule, VulnerabilityResult } from "./types";

interface CookieDetails {
  name: string;
  value: string;
  httponly: boolean;
  secure: boolean;
  samesite: string | null;
  domain: string | null;
  path: string | null;
}

/**
 * Parse Set-Cookie headers and check for missing security flags:
 *  - HttpOnly
 *  - Secure
 *  - SameSite
 * Flag session cookies without proper protection.
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const cookies = await fetchCookies(targetUrl);

  if (cookies.length === 0) {
    return findings;
  }

  const sessionCookiePatterns = [
    /^(sess|session|sid|jsession|phpsessid|asp\.net_session|laravel_session|connect\.sid|token|auth)/i,
  ];

  for (const cookie of cookies) {
    const isLikelySession = sessionCookiePatterns.some((p) => p.test(cookie.name));

    if (isLikelySession) {
      if (!cookie.httponly) {
        findings.push({
          severity: "high",
          category: "Cookies",
          title: `Session cookie "${cookie.name}" missing HttpOnly flag`,
          description: `The cookie "${cookie.name}" appears to be a session cookie but does not have the HttpOnly flag set. This makes it accessible to JavaScript, increasing the risk of theft via XSS.`,
          evidence: `Set-Cookie: ${formatCookie(cookie)}`,
          remediation: `Set the HttpOnly flag on the "${cookie.name}" cookie to prevent client-side script access.`,
          cvssScore: 6.1,
          affectedUrl: targetUrl,
        });
      }

      if (!cookie.secure) {
        findings.push({
          severity: "medium",
          category: "Cookies",
          title: `Session cookie "${cookie.name}" missing Secure flag`,
          description: `The cookie "${cookie.name}" does not have the Secure flag set. It will be transmitted over plain HTTP connections, exposing it to network-level eavesdropping.`,
          evidence: `Set-Cookie: ${formatCookie(cookie)}`,
          remediation: `Set the Secure flag on the "${cookie.name}" cookie so it is only sent over HTTPS.`,
          cvssScore: 4.3,
          affectedUrl: targetUrl,
        });
      }

      if (!cookie.samesite) {
        findings.push({
          severity: "medium",
          category: "Cookies",
          title: `Session cookie "${cookie.name}" missing SameSite attribute`,
          description: `The cookie "${cookie.name}" does not have a SameSite attribute. This makes it vulnerable to Cross-Site Request Forgery (CSRF) attacks where the cookie is sent with cross-origin requests.`,
          evidence: `Set-Cookie: ${formatCookie(cookie)}`,
          remediation: `Set SameSite=Strict or SameSite=Lax on the "${cookie.name}" cookie.`,
          cvssScore: 4.3,
          affectedUrl: targetUrl,
        });
      }
    } else {
      // Non-session cookies: still flag missing Secure flag on HTTPS sites
      const isHttps = new URL(targetUrl).protocol === "https:";
      if (isHttps && !cookie.secure) {
        findings.push({
          severity: "low",
          category: "Cookies",
          title: `Cookie "${cookie.name}" missing Secure flag on HTTPS site`,
          description: `The cookie "${cookie.name}" is set on an HTTPS page but lacks the Secure flag, meaning it could be sent over HTTP.`,
          evidence: `Set-Cookie: ${formatCookie(cookie)}`,
          remediation: `Set the Secure flag on the "${cookie.name}" cookie.`,
          cvssScore: 2.0,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseSetCookie(headerValue: string): CookieDetails {
  const parts = headerValue.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const eqIdx = nameValue.indexOf("=");
  const name = eqIdx >= 0 ? nameValue.substring(0, eqIdx).trim() : nameValue.trim();
  const value = eqIdx >= 0 ? nameValue.substring(eqIdx + 1).trim() : "";

  let httponly = false;
  let secure = false;
  let samesite: string | null = null;
  let domain: string | null = null;
  let path: string | null = null;

  for (const attr of attrs) {
    const lower = attr.toLowerCase();
    if (lower === "httponly") httponly = true;
    else if (lower === "secure") secure = true;
    else if (lower.startsWith("samesite=")) samesite = attr.substring(9).trim();
    else if (lower.startsWith("domain=")) domain = attr.substring(7).trim();
    else if (lower.startsWith("path=")) path = attr.substring(5).trim();
  }

  return { name, value, httponly, secure, samesite, domain, path };
}

function formatCookie(cookie: CookieDetails): string {
  const parts = [`${cookie.name}=${cookie.value}`];
  if (cookie.httponly) parts.push("HttpOnly");
  if (cookie.secure) parts.push("Secure");
  if (cookie.samesite) parts.push(`SameSite=${cookie.samesite}`);
  if (cookie.domain) parts.push(`Domain=${cookie.domain}`);
  if (cookie.path) parts.push(`Path=${cookie.path}`);
  return parts.join("; ");
}

function fetchCookies(targetUrl: string): Promise<CookieDetails[]> {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const lib = parsed.protocol === "https:" ? https : http;

    const options: https.RequestOptions = {
      method: "GET",
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        "User-Agent": "SecuPi-Scanner/1.0",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      timeout: 10000,
    };

    const req = lib.request(options, (res) => {
      const setCookieHeaders = res.headers["set-cookie"] as string[] | undefined;
      const cookies: CookieDetails[] = [];

      if (setCookieHeaders && Array.isArray(setCookieHeaders)) {
        for (const h of setCookieHeaders) {
          cookies.push(parseSetCookie(h));
        }
      }

      resolve(cookies);
      res.resume();
    });

    req.on("error", () => resolve([]));
    req.on("timeout", () => {
      req.destroy();
      resolve([]);
    });

    req.end();
  });
}
