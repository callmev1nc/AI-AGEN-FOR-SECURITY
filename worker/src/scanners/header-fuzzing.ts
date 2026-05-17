import * as http from "http";
import * as https from "https";
import type { ScannerModule, VulnerabilityResult } from "./types";
import { getHeader } from "./types";

/**
 * Header fuzzing:
 *  - CRLF injection via URL parameters
 *  - HTTP response splitting
 *  - Header injection via common parameters
 *  - Host header attacks
 *  - X-Forwarded-* header manipulation
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const parsed = new URL(targetUrl);

  // ---- 1. CRLF injection via URL parameters ----
  const crlfPayloads = [
    { param: "q", value: "test%0d%0aInjected-Header: secupi-crlf", label: "CRLF via query param" },
    { param: "redirect", value: "https://example.com%0d%0aInjected-Header: secupi-crlf", label: "CRLF via redirect param" },
    { param: "url", value: "https://example.com%0d%0aInjected-Header: secupi-crlf", label: "CRLF via URL param" },
    { param: "next", value: "/page%0d%0aInjected-Header: secupi-crlf", label: "CRLF via next param" },
    { param: "return", value: "/home%0d%0aInjected-Header: secupi-crlf", label: "CRLF via return param" },
  ];

  for (const payload of crlfPayloads) {
    const testUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${payload.param}=${payload.value}`;
    const resp = await sendRequest(testUrl, "GET", {});
    if (resp) {
      // Check if the injected header appears in the response headers
      const h = resp.headers as unknown as Record<string, unknown>;
      if (getHeader(h, "injected-header")) {
        findings.push({
          severity: "high",
          category: "Header Injection",
          title: `CRLF injection via "${payload.param}" parameter`,
          description: `The "${payload.param}" parameter is vulnerable to CRLF injection. The injected header "Injected-Header" appeared in the server response. An attacker can inject arbitrary response headers, enabling cache poisoning, XSS via headers, and HTTP response splitting.`,
          evidence: `Injected-Header found in response: ${getHeader(h, "injected-header")}`,
          remediation: "Sanitize all user input used in HTTP headers. Encode CR (%0d) and LF (%0a) characters. Use framework-level URL encoding.",
          cvssScore: 7.5,
          affectedUrl: testUrl,
        });
      }

      // Check if the payload appears in the response body (reflection)
      const decodedValue = payload.value.replace(/%0d%0a/g, "\r\n");
      if (resp.body && resp.body.includes(decodedValue.split("\r\n")[0])) {
        findings.push({
          severity: "medium",
          category: "Header Injection",
          title: `CRLF payload reflected in response via "${payload.param}"`,
          description: `The CRLF payload value is reflected in the response body via the "${payload.param}" parameter. While the header injection did not succeed, the reflection may indicate insufficient input validation.`,
          evidence: `Payload reflected in response body`,
          remediation: "Sanitize all user input. Remove CR and LF characters from user-supplied values before including them in HTTP responses.",
          cvssScore: 4.3,
          affectedUrl: testUrl,
        });
      }
    }
  }

  // ---- 2. HTTP response splitting via double CRLF ----
  const responseSplitPayloads = [
    "%0d%0a%0d%0a<html><body>secupi-response-splitting-test</body></html>",
    "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>injected</html>",
  ];

  for (const payload of responseSplitPayloads) {
    const testUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?q=${payload}`;
    const resp = await sendRequest(testUrl, "GET", {});
    if (resp && resp.body && resp.body.includes("secupi-response-splitting-test")) {
      findings.push({
        severity: "high",
        category: "Header Injection",
        title: "HTTP response splitting possible",
        description: "The application is vulnerable to HTTP response splitting. An attacker can inject a full HTTP response body, enabling cache poisoning and phishing attacks.",
        evidence: "Injected HTML content appeared in the response body",
        remediation: "Encode all CRLF sequences in user input. Use modern HTTP frameworks that prevent header injection.",
        cvssScore: 7.5,
        affectedUrl: testUrl,
      });
    }
  }

  // ---- 3. Host header attacks ----
  const hostPayloads = [
    { host: "evil.com", label: "malicious host" },
    { host: `${parsed.hostname}@evil.com`, label: "host with @ symbol" },
    { host: `evil.com${parsed.hostname}`, label: "host prefix" },
    { host: `${parsed.hostname}:9999`, label: "port manipulation" },
    { host: `${parsed.hostname}\r\nInjected-Header: secupi-host-crlf`, label: "CRLF in host" },
  ];

  for (const payload of hostPayloads) {
    const resp = await sendRequest(targetUrl, "GET", { Host: payload.host });
    if (resp) {
      // Check if the malicious host appears in response body (used in password reset links, etc.)
      if (resp.body && resp.body.includes("evil.com")) {
        findings.push({
          severity: "high",
          category: "Header Injection",
          title: `Host header injection: ${payload.label}`,
          description: `The server reflects the Host header value in the response body. An attacker can manipulate the Host header to poison password reset links, cacheable pages, or CSRF tokens.`,
          evidence: `Host "${payload.host}" reflected in response body`,
          remediation:
            "Validate the Host header against a whitelist of allowed domains. Use the X-Forwarded-Host header carefully. Configure virtual hosts properly.",
          cvssScore: 7.5,
          affectedUrl: targetUrl,
        });
      }

      // Check for CRLF in host header
      const h2 = resp.headers as unknown as Record<string, unknown>;
      if (getHeader(h2, "injected-header")) {
        findings.push({
          severity: "high",
          category: "Header Injection",
          title: "CRLF injection via Host header",
          description: "The Host header is vulnerable to CRLF injection, allowing injection of arbitrary response headers.",
          evidence: `Injected-Header found in response via Host header CRLF`,
          remediation: "Validate and sanitize the Host header. Reject requests with CRLF characters in the Host header.",
          cvssScore: 7.5,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  // ---- 4. X-Forwarded-* header manipulation ----
  const forwardTests: Array<{
    headers: Record<string, string>;
    label: string;
    description: string;
    severity: VulnerabilityResult["severity"];
    cvss: number;
  }> = [
    {
      headers: { "X-Forwarded-Host": "evil.com" },
      label: "X-Forwarded-Host spoofing",
      description: "The server trusts the X-Forwarded-Host header without validation. An attacker can spoof this header to manipulate generated URLs (password resets, links).",
      severity: "medium",
      cvss: 5.3,
    },
    {
      headers: { "X-Forwarded-Proto": "http" },
      label: "X-Forwarded-Proto downgrade",
      description: "The server trusts X-Forwarded-Proto to determine the protocol. An attacker can downgrade the perceived protocol from HTTPS to HTTP, potentially bypassing security checks.",
      severity: "medium",
      cvss: 4.3,
    },
    {
      headers: { "X-Original-URL": "/admin" },
      label: "X-Original-URL bypass",
      description: "The server may use X-Original-URL for routing decisions. Some reverse proxies (e.g., IIS ARR) can be bypassed using this header to access restricted paths.",
      severity: "medium",
      cvss: 5.3,
    },
    {
      headers: { "X-Rewrite-URL": "/admin" },
      label: "X-Rewrite-URL bypass",
      description: "The server may use X-Rewrite-URL for routing. Similar to X-Original-URL, this can bypass access controls.",
      severity: "medium",
      cvss: 5.3,
    },
    {
      headers: { "X-Forwarded-For": "127.0.0.1" },
      label: "X-Forwarded-For IP spoofing",
      description: "The server trusts X-Forwarded-For for IP-based access control. An attacker can spoof the IP to bypass IP restrictions or rate limiting.",
      severity: "low",
      cvss: 3.1,
    },
  ];

  for (const test of forwardTests) {
    const resp = await sendRequest(targetUrl, "GET", test.headers);
    if (resp) {
      // Check if the spoofed value appears in the response
      const spoofedValue = Object.values(test.headers)[0];
      if (resp.body && resp.body.includes(spoofedValue)) {
        findings.push({
          severity: test.severity,
          category: "Header Injection",
          title: test.label,
          description: test.description,
          evidence: `Value "${spoofedValue}" from ${Object.keys(test.headers)[0]} reflected in response body`,
          remediation:
            "Do not trust X-Forwarded-* headers without validation. Configure the reverse proxy to overwrite (not append) these headers. Use a known list of trusted proxy IPs.",
          cvssScore: test.cvss,
          affectedUrl: targetUrl,
        });
      }

      // Check for different response status/size (access control bypass)
      const normalResp = await sendRequest(targetUrl, "GET", {});
      if (normalResp && resp.statusCode !== normalResp.statusCode) {
        const normalStatus = normalResp.statusCode;
        const spoofedStatus = resp.statusCode;
        if (
          (normalStatus === 403 && spoofedStatus === 200) ||
          (normalStatus === 401 && spoofedStatus === 200)
        ) {
          findings.push({
            severity: "high",
            category: "Header Injection",
            title: `Access control bypass via ${test.label}`,
            description: `The server returns HTTP ${normalStatus} normally but HTTP ${spoofedStatus} when the ${Object.keys(test.headers)[0]} header is spoofed. This indicates the header is trusted for access control decisions.`,
            evidence: `Normal: HTTP ${normalStatus}, With header: HTTP ${spoofedStatus}`,
            remediation:
              "Do not use X-Forwarded-* headers for authentication or authorization decisions. Validate these headers only against trusted proxy IPs.",
            cvssScore: 8.1,
            affectedUrl: targetUrl,
          });
        }
      }
    }
  }

  // ---- 5. Content-Type and Accept header fuzzing ----
  const contentTests: Array<{ headers: Record<string, string>; label: string }> = [
    {
      headers: { Accept: "application/json" },
      label: "JSON Accept header",
    },
    {
      headers: { Accept: "application/xml" },
      label: "XML Accept header",
    },
    {
      headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
      label: "AJAX request",
    },
  ];

  for (const test of contentTests) {
    const resp = await sendRequest(targetUrl, "GET", test.headers);
    if (resp && resp.body) {
      const leak = checkForInfoLeak(resp.body);
      if (leak) {
        findings.push({
          severity: "low",
          category: "Header Injection",
          title: `Information leak with ${test.label}`,
          description: `Using ${test.label}, the server response includes ${leak.type} information: ${leak.summary}`,
          evidence: truncate(leak.evidence, 300),
          remediation: "Ensure all response content types return sanitized error messages.",
          cvssScore: 3.1,
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

interface RawResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function sendRequest(
  url: string,
  method: string,
  extraHeaders: Record<string, string>
): Promise<RawResponse | null> {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;

    const options: https.RequestOptions = {
      method,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        "User-Agent": "SecuPi-Scanner/1.0",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ...extraHeaders,
      },
      timeout: 8000,
    };

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer | string) => {
        if (typeof chunk === "string") chunks.push(Buffer.from(chunk));
        else chunks.push(chunk);
      });
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode || 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });

    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });

    req.end();
  });
}

interface LeakInfo {
  type: string;
  summary: string;
  evidence: string;
}

function checkForInfoLeak(body: string): LeakInfo | null {
  if (!body) return null;

  const patterns: Array<{ pattern: RegExp; type: string; summary: string }> = [
    {
      pattern: /at\s+[\w.$]+\s+\([^)]*\.(js|ts):?\d+:\d+\)/,
      type: "stack trace",
      summary: "a server-side stack trace",
    },
    {
      pattern: /Traceback\s*\(most recent call last\)/,
      type: "Python traceback",
      summary: "a Python stack trace",
    },
    {
      pattern: /\/(?:home|var|usr|etc|opt|app)\/[\w./]+\.(?:php|py|rb|js|ts|conf)/,
      type: "file path",
      summary: "a server-side file path",
    },
    {
      pattern: /SQLSTATE\[\w+\]/i,
      type: "SQL error",
      summary: "a SQL error message",
    },
  ];

  for (const { pattern, type, summary } of patterns) {
    if (pattern.test(body)) {
      return { type, summary, evidence: body.substring(0, 500) };
    }
  }

  return null;
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.substring(0, maxLen) + "...";
}
