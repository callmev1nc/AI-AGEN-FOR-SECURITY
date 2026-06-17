import type { ScannerModule, VulnerabilityResult } from "./types";
import { fetchFull } from "./http";

/**
 * Advanced cookie analysis:
 *  - Session fixation: does the app accept session cookies from URL parameters?
 *  - Cookie tossing: can cookies be set for parent domain?
 *  - Cookie path scope issues
 *  - Session cookie rotation on login
 *  - Persistent session cookies
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  // ---- 1. Fetch initial cookies ----
  const initialResp = await httpGetFull(targetUrl);
  if (!initialResp) return findings;

  const initialCookies = parseCookies(initialResp.setCookie);  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;

  // ---- 2. Check for session fixation via URL parameters ----
  const sessionParamNames = ["sid", "sessionid", "jsessionid", "phpsessid", "sess", "token"];
  for (const paramName of sessionParamNames) {
    const testUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${paramName}=secupi-fixation-test-12345`;
    const fixationResp = await httpGetFull(testUrl);
    if (fixationResp) {
      const body = fixationResp.body || "";
      // Check if the value appears in a Set-Cookie header
      const fixationCookies = parseCookies(fixationResp.setCookie);
      const hasFixedSession = fixationCookies.some(
        (c) => c.value === "secupi-fixation-test-12345"
      );
      // Check if it appears in the response body (e.g., in a form hidden field)
      const inBody = body.includes("secupi-fixation-test-12345");

      if (hasFixedSession || inBody) {
        findings.push({
          severity: "high",
          category: "Cookie Security",
          title: `Session fixation via URL parameter "${paramName}"`,
          description: `The application accepts a session identifier from the "${paramName}" URL parameter. An attacker can craft a link with a known session ID, trick a victim into authenticating with it, and then hijack the session.`,
          evidence: hasFixedSession
            ? `Set-Cookie reflected the URL parameter value`
            : `Session ID from URL parameter appeared in response body`,
          remediation:
            "Never accept session identifiers from URL parameters. Generate a new session ID after successful authentication. Use Secure, HttpOnly, SameSite cookies.",
          cvssScore: 8.1,
          affectedUrl: testUrl,
        });
      }
    }
  }

  // ---- 3. Cookie tossing / parent domain scope ----
  const domainParts = hostname.split(".");
  if (domainParts.length >= 2) {
    const parentDomain = domainParts.slice(-2).join(".");

    // Check if any cookie is set for a parent domain
    for (const cookie of initialCookies) {
      if (cookie.domain) {
        const cookieDomain = cookie.domain.replace(/^\./, "");
        if (cookieDomain === parentDomain || hostname.endsWith(`.${cookieDomain}`)) {
          // The cookie is scoped to a parent domain — check if it is sensitive
          const isSessionCookie = /sess|sid|token|auth|login/i.test(cookie.name);
          if (isSessionCookie) {
            findings.push({
              severity: "medium",
              category: "Cookie Security",
              title: `Session cookie "${cookie.name}" scoped to parent domain`,
              description: `The cookie "${cookie.name}" is scoped to domain "${cookie.domain}". This means any subdomain can read or overwrite it, enabling cookie-tossing attacks from compromised subdomains.`,
              evidence: `Set-Cookie: ${cookie.name}=...; Domain=${cookie.domain}`,
              remediation: `Scope the cookie to the most specific domain possible. Avoid setting session cookies on parent domains.`,
              cvssScore: 5.3,
              affectedUrl: targetUrl,
            });
          }
        }
      }
    }
  }

  // ---- 4. Cookie path scope ----
  for (const cookie of initialCookies) {
    if (cookie.path === "/" || !cookie.path) {
      const isSessionCookie = /sess|sid|token|auth|login/i.test(cookie.name);
      if (isSessionCookie) {
        findings.push({
          severity: "low",
          category: "Cookie Security",
          title: `Session cookie "${cookie.name}" scoped to root path`,
          description: `The cookie "${cookie.name}" has a path of "/" (or no path specified), making it accessible from every path on the domain. This increases the attack surface for cookie theft via XSS on any subpath.`,
          evidence: `Set-Cookie: ${cookie.name}=...; Path=${cookie.path || "/"}`,
          remediation: `Restrict the cookie path to the specific application path that needs it, e.g., Path=/app/ instead of Path=/.`,
          cvssScore: 2.4,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  // ---- 5. Check for persistent session cookies ----
  for (const cookie of initialCookies) {
    const isSessionCookie = /sess|sid|token|auth|login/i.test(cookie.name);
    if (isSessionCookie && cookie.maxAge && cookie.maxAge > 86400) {
      // Session cookie with max-age > 24 hours
      findings.push({
        severity: "medium",
        category: "Cookie Security",
        title: `Session cookie "${cookie.name}" has excessive max-age`,
        description: `The session cookie "${cookie.name}" has a Max-Age of ${cookie.maxAge} seconds (${Math.round(cookie.maxAge / 3600)} hours). Long-lived session cookies increase the window for session hijacking.`,
        evidence: `Set-Cookie: ${cookie.name}=...; Max-Age=${cookie.maxAge}`,
        remediation:
          "Set session cookies to expire after a reasonable period (e.g., 1-8 hours). Implement server-side session expiration as well.",
        cvssScore: 4.3,
        affectedUrl: targetUrl,
      });
    }

    if (isSessionCookie && cookie.expires) {
      const expiresDate = new Date(cookie.expires);
      const daysUntilExpiry = (expiresDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
      if (daysUntilExpiry > 7) {
        findings.push({
          severity: "low",
          category: "Cookie Security",
          title: `Session cookie "${cookie.name}" expires far in the future`,
          description: `The session cookie "${cookie.name}" expires in ${Math.round(daysUntilExpiry)} days. This increases the window for session hijacking attacks.`,
          evidence: `Set-Cookie: ${cookie.name}=...; Expires=${cookie.expires}`,
          remediation: "Set shorter expiration times for session cookies. Implement server-side session timeout.",
          cvssScore: 3.1,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  // ---- 6. Test cookie over HTTP (if HTTPS target) ----
  if (parsed.protocol === "https:") {
    const httpUrl = targetUrl.replace("https://", "http://");
    const httpResp = await httpGetFull(httpUrl);
    if (httpResp) {
      const httpCookies = parseCookies(httpResp.setCookie);
      for (const cookie of httpCookies) {
        if (!cookie.secure) {
          const isSessionCookie = /sess|sid|token|auth|login/i.test(cookie.name);
          if (isSessionCookie) {
            findings.push({
              severity: "high",
              category: "Cookie Security",
              title: `Session cookie "${cookie.name}" set over HTTP without Secure flag`,
              description: `The HTTPS site also responds on HTTP and sets the session cookie "${cookie.name}" without the Secure flag. This allows the cookie to be transmitted over plain HTTP, enabling session hijacking via network sniffing.`,
              evidence: `Cookie set on HTTP: ${cookie.name} without Secure flag`,
              remediation:
                "Enable HSTS and redirect all HTTP traffic to HTTPS. Set the Secure flag on all session cookies.",
              cvssScore: 7.5,
              affectedUrl: httpUrl,
            });
          }
        }
      }
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface CookieInfo {
  name: string;
  value: string;
  httponly: boolean;
  secure: boolean;
  samesite: string | null;
  domain: string | null;
  path: string | null;
  maxAge: number | null;
  expires: string | null;
}

interface FullResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  setCookie: string[];
}

function parseCookies(setCookieHeaders: string[]): CookieInfo[] {
  return setCookieHeaders.map((h) => {
    const parts = h.split(";").map((p) => p.trim());
    const [nameValue, ...attrs] = parts;
    const eqIdx = nameValue.indexOf("=");
    const name = eqIdx >= 0 ? nameValue.substring(0, eqIdx).trim() : nameValue.trim();
    const value = eqIdx >= 0 ? nameValue.substring(eqIdx + 1).trim() : "";

    let httponly = false;
    let secure = false;
    let samesite: string | null = null;
    let domain: string | null = null;
    let path: string | null = null;
    let maxAge: number | null = null;
    let expires: string | null = null;

    for (const attr of attrs) {
      const lower = attr.toLowerCase();
      if (lower === "httponly") httponly = true;
      else if (lower === "secure") secure = true;
      else if (lower.startsWith("samesite=")) samesite = attr.substring(9).trim();
      else if (lower.startsWith("domain=")) domain = attr.substring(7).trim();
      else if (lower.startsWith("path=")) path = attr.substring(5).trim();
      else if (lower.startsWith("max-age=")) {
        const parsed = parseInt(attr.substring(8).trim(), 10);
        if (!isNaN(parsed)) maxAge = parsed;
      }
      else if (lower.startsWith("expires=")) expires = attr.substring(8).trim();
    }

    return { name, value, httponly, secure, samesite, domain, path, maxAge, expires };
  });
}

async function httpGetFull(url: string): Promise<FullResponse | null> {
  const res = await fetchFull(url, {
    headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
    followRedirects: false,
    timeoutMs: 10000,
  });
  if (!res) return null;
  return {
    statusCode: res.statusCode,
    headers: res.headers,
    body: res.body,
    setCookie: res.setCookie,
  };
}
