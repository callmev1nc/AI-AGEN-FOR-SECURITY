import * as http from "http";
import * as https from "https";
import type { ScannerModule, VulnerabilityResult } from "./types";
import { getHeader } from "./types";

/**
 * Advanced CORS testing:
 *  - null origin reflection
 *  - Special characters in origin
 *  - Long origins
 *  - Origin with @ symbol (user@host bypass)
 *  - Subdomain takeover scenarios
 *  - Trust of arbitrary subdomains
 *  - Regex-based origin validation bypass
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;

  // ---- Test cases ----
  const testCases: Array<{
    origin: string;
    label: string;
    severity: VulnerabilityResult["severity"];
    description: string;
    cvss: number;
  }> = [
    {
      origin: "null",
      label: "null origin",
      severity: "high",
      description:
        "The server reflects the 'null' origin. This can be exploited via sandboxed iframes (<iframe sandbox>) and cross-origin redirects that set the origin to 'null'.",
      cvss: 7.5,
    },
    {
      origin: `https://${hostname}.evil.com`,
      label: "subdomain suffix bypass",
      severity: "high",
      description:
        "The server trusts origins ending with the target domain name. This can be exploited if an attacker controls evil.com and registers target.evil.com. The server likely uses a flawed suffix-match check.",
      cvss: 8.1,
    },
    {
      origin: `https://evil${hostname}`,
      label: "prefix concatenation bypass",
      severity: "medium",
      description:
        "The server may be doing string containment checks. If 'evil' is prepended to the hostname, a flawed contains() or indexOf() check may match.",
      cvss: 5.3,
    },
    {
      origin: `https://evil.com\\@${hostname}`,
      label: "backslash-at bypass",
      severity: "high",
      description:
        "The server may incorrectly parse the @ symbol in the origin. Some implementations treat everything before @ as credentials, allowing bypass via crafted origins.",
      cvss: 7.5,
    },
    {
      origin: `https://evil.com%00@${hostname}`,
      label: "null byte bypass",
      severity: "high",
      description:
        "Null byte injection in the origin header. Some servers truncate at the null byte while browsers include it, causing a mismatch in origin validation.",
      cvss: 7.5,
    },
    {
      origin: `https://evil.com%0d%0a${hostname}`,
      label: "CRLF in origin",
      severity: "medium",
      description:
        "CRLF characters in the origin header may bypass flawed validation logic that splits on newlines or uses regex without multiline anchors.",
      cvss: 5.3,
    },
    {
      origin: `https://user:pass@${hostname}`,
      label: "credentials in origin",
      severity: "medium",
      description:
        "Embedding credentials in the origin URL. Some validation logic may strip the credentials portion and match the remaining host.",
      cvss: 5.3,
    },
    {
      origin: `https://${hostname}%00.evil.com`,
      label: "null byte subdomain bypass",
      severity: "medium",
      description:
        "Null byte in a subdomain. Some origin validators may truncate at the null byte and accept the origin as matching the target.",
      cvss: 5.3,
    },
    {
      origin: `https://${hostname.replace(".", "..")}`,
      label: "dot bypass",
      severity: "low",
      description:
        "Double-dot in hostname. Edge case that may bypass simplistic domain matching.",
      cvss: 3.1,
    },
    {
      origin: "A".repeat(200) + `.com`,
      label: "long origin (buffer issue)",
      severity: "low",
      description:
        "An extremely long origin value. Some implementations may truncate or mishandle very long strings, leading to validation bypass.",
      cvss: 3.1,
    },
    {
      origin: `https://127.0.0.1`,
      label: "localhost IP origin",
      severity: "medium",
      description:
        "The server trusts localhost/loopback addresses as origins. If developer tools or local services run on 127.0.0.1, this could be exploited.",
      cvss: 4.3,
    },
    {
      origin: `https://[${hostname}].evil.com`,
      label: "bracketed subdomain bypass",
      severity: "medium",
      description:
        "Square brackets around the hostname in a subdomain of evil.com. May bypass regex-based validation that does not account for brackets.",
      cvss: 4.3,
    },
  ];

  for (const tc of testCases) {
    const resp = await sendCorsPreflight(targetUrl, tc.origin);
    if (!resp) continue;

    const acao = getHeader(resp.headers as unknown as Record<string, unknown>, "access-control-allow-origin");
    const acac = getHeader(resp.headers as unknown as Record<string, unknown>, "access-control-allow-credentials");

    // Check if the origin was reflected
    if (acao === tc.origin || acao === "*") {
      const withCreds = acac === "true";
      const effectiveSeverity: VulnerabilityResult["severity"] = withCreds
        ? tc.severity === "low"
          ? "medium"
          : tc.severity
        : tc.severity === "high"
          ? "medium"
          : tc.severity;

      findings.push({
        severity: effectiveSeverity,
        category: "CORS",
        title: `CORS origin validation bypass: ${tc.label}`,
        description: tc.description + (withCreds ? " Credentials are also allowed (ACAC: true), increasing the risk." : ""),
        evidence: `Origin: ${tc.origin} -> ACAO: ${acao}${acac ? `, ACAC: ${acac}` : ""}`,
        remediation:
          "Implement strict origin validation using an exact-match whitelist. Avoid regex-based or suffix-based checks. Use a Set or Map of explicitly allowed origins.",
        cvssScore: withCreds ? tc.cvss + 1.0 : tc.cvss,
        affectedUrl: targetUrl,
      });
    }
  }

  // ---- Check for trust of all subdomains ----
  const subdomainOrigin = `https://test-attacker.${hostname}`;
  const subResp = await sendCorsPreflight(targetUrl, subdomainOrigin);
  if (subResp) {
    const acao = getHeader(subResp.headers as unknown as Record<string, unknown>, "access-control-allow-origin");
    const acac = getHeader(subResp.headers as unknown as Record<string, unknown>, "access-control-allow-credentials");
    if (acao === subdomainOrigin) {
      findings.push({
        severity: acac === "true" ? "high" : "medium",
        category: "CORS",
        title: "CORS trusts arbitrary subdomains",
        description: `The server reflects the subdomain origin ${subdomainOrigin}. This indicates it trusts any subdomain. If any subdomain is compromised or a DNS subdomain takeover is possible, an attacker can fully exploit CORS.`,
        evidence: `Origin: ${subdomainOrigin} -> ACAO: ${acao}, ACAC: ${acac || "not set"}`,
        remediation:
          "Do not trust all subdomains. Explicitly list the subdomains that should be allowed. Implement DNS CNAME monitoring to detect subdomain takeover risks.",
        cvssScore: acac === "true" ? 8.1 : 5.3,
        affectedUrl: targetUrl,
      });
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sendCorsPreflight(
  targetUrl: string,
  origin: string
): Promise<http.IncomingHttpHeaders | null> {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const lib = parsed.protocol === "https:" ? https : http;

    const options: https.RequestOptions = {
      method: "OPTIONS",
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Content-Type, Authorization, X-Custom-Header",
        "User-Agent": "SecuPi-Scanner/1.0",
      },
      timeout: 8000,
    };

    const req = lib.request(options, (res) => {
      resolve(res.headers);
      res.resume();
    });

    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });

    req.end();
  });
}
