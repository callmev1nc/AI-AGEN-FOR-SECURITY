import * as http from "http";
import * as https from "https";
import type { ScannerModule, VulnerabilityResult } from "./types";

/**
 * Check for missing or misconfigured security headers.
 * Makes an HTTP GET request and inspects the response headers.
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  const headers = await fetchHeaders(targetUrl);
  if (!headers) {
    return findings;
  }

  const checks: Array<{
    name: string;
    header: string;
    severity: VulnerabilityResult["severity"];
    description: string;
    remediation: string;
    cvss: number;
  }> = [
    {
      name: "Strict-Transport-Security",
      header: "strict-transport-security",
      severity: "high",
      description:
        "The Strict-Transport-Security (HSTS) header is missing. Without HSTS, browsers may attempt to connect via plain HTTP before redirecting to HTTPS, exposing the user to SSL stripping attacks.",
      remediation:
        "Add the Strict-Transport-Security header. Recommended value: `strict-transport-security: max-age=31536000; includeSubDomains; preload`.",
      cvss: 6.5,
    },
    {
      name: "Content-Security-Policy",
      header: "content-security-policy",
      severity: "high",
      description:
        "The Content-Security-Policy (CSP) header is missing. Without CSP the browser has no restrictions on which origins it may load scripts, styles, images, frames, etc. from, greatly increasing the impact of XSS vulnerabilities.",
      remediation:
        "Define a Content-Security-Policy that limits script-src, style-src, and other directives to trusted origins. Start with `default-src 'self'` and relax as needed.",
      cvss: 6.1,
    },
    {
      name: "X-Frame-Options",
      header: "x-frame-options",
      severity: "medium",
      description:
        "The X-Frame-Options header is missing. An attacker can embed the page in an invisible iframe to perform clickjacking attacks.",
      remediation:
        "Set `X-Frame-Options: DENY` or `SAMEORIGIN`. Note: CSP frame-ancestors directive is the modern replacement, but X-Frame-Options is still recommended for older browser support.",
      cvss: 4.3,
    },
    {
      name: "X-Content-Type-Options",
      header: "x-content-type-options",
      severity: "low",
      description:
        "The X-Content-Type-Options header is missing. Without `nosniff`, browsers may MIME-sniff responses and interpret them in unexpected ways (e.g., render a JSON response as HTML).",
      remediation: "Set `X-Content-Type-Options: nosniff`.",
      cvss: 2.6,
    },
    {
      name: "Referrer-Policy",
      header: "referrer-policy",
      severity: "low",
      description:
        "The Referrer-Policy header is missing. Browsers will use their default (typically `no-referrer-when-downgrade`), which may leak full URLs including path and query parameters to third-party origins.",
      remediation:
        "Set an appropriate Referrer-Policy such as `strict-origin-when-cross-origin` or `no-referrer`.",
      cvss: 2.4,
    },
    {
      name: "Permissions-Policy",
      header: "permissions-policy",
      severity: "low",
      description:
        "The Permissions-Policy header is missing. Without it the browser allows any page content to request access to powerful features like camera, microphone, geolocation, etc.",
      remediation:
        "Set a Permissions-Policy that explicitly denies or restricts features not required by the application. Example: `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
      cvss: 2.0,
    },
  ];

  for (const check of checks) {
    const rawValue = headers[check.header];
    const value = Array.isArray(rawValue) ? rawValue[0] : rawValue;
    if (!value) {
      findings.push({
        severity: check.severity,
        category: "Security Headers",
        title: `Missing ${check.name} header`,
        description: check.description,
        remediation: check.remediation,
        cvssScore: check.cvss,
        affectedUrl: targetUrl,
      });
    } else {
      // Additional validation for specific headers
      if (check.header === "strict-transport-security") {
        const maxAgeMatch = value.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1], 10);
          if (maxAge < 2592000) {
            // Less than 30 days
            findings.push({
              severity: "medium",
              category: "Security Headers",
              title: "Weak HSTS max-age value",
              description: `Strict-Transport-Security max-age is set to ${maxAge} seconds (less than the recommended 30 days). Short max-age values reduce protection effectiveness.`,
              evidence: `strict-transport-security: ${value}`,
              remediation:
                "Increase the max-age to at least 31536000 seconds (1 year). Recommended: `strict-transport-security: max-age=31536000; includeSubDomains; preload`.",
              cvssScore: 3.7,
              affectedUrl: targetUrl,
            });
          }
        }
      }

      if (check.header === "content-security-policy") {
        if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
          findings.push({
            severity: "medium",
            category: "Security Headers",
            title: "Weak Content-Security-Policy",
            description:
              "The CSP contains 'unsafe-inline' or 'unsafe-eval' directives which significantly weaken XSS protection.",
            evidence: `content-security-policy: ${value}`,
            remediation:
              "Remove 'unsafe-inline' and 'unsafe-eval' from the CSP. Use nonce-based or hash-based CSP instead.",
            cvssScore: 5.0,
            affectedUrl: targetUrl,
          });
        }
      }
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fetchHeaders(targetUrl: string): Promise<http.IncomingHttpHeaders | null> {
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
      resolve(res.headers);
      res.resume(); // drain the response so the socket can be reused
    });

    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });

    req.end();
  });
}
