import * as http from "http";
import * as https from "https";
import type { ScannerModule, VulnerabilityResult } from "./types";

/**
 * Send malformed requests to trigger errors:
 *  - Very long URLs
 *  - Special characters in paths
 *  - Malformed HTTP methods
 *  - Oversized headers
 * Check if error messages leak stack traces, file paths, database info.
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const parsed = new URL(targetUrl);

  // ---- 1. Very long URL ----
  const longPath = "/test/" + "A".repeat(8000);
  const longUrl = `${parsed.protocol}//${parsed.host}${longPath}`;
  const longResp = await sendRawRequest(longUrl, "GET", {});
  if (longResp) {
    const leaked = checkForInfoLeak(longResp.body);
    if (leaked) {
      findings.push({
        severity: "medium",
        category: "Error Handling",
        title: `Information leak via long URL (${leaked.type})`,
        description: `Sending a very long URL (${longPath.length} characters) triggers an error response that leaks ${leaked.type} information: ${leaked.summary}`,
        evidence: truncate(leaked.evidence, 500),
        remediation: "Implement a generic error handler that returns standardized error pages without internal details. Reject oversized URLs at the reverse proxy level.",
        cvssScore: 5.3,
        affectedUrl: longUrl,
      });
    }
  }

  // ---- 2. Special characters in path ----
  const specialPaths = [
    { path: "/%00", label: "null byte in path" },
    { path: "/%0d%0a", label: "CRLF in path" },
    { path: "/..%252f..%252f..%252fetc/passwd", label: "double-encoded path traversal" },
    { path: "/....//....//....//etc/passwd", label: "path traversal variant" },
    { path: "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", label: "unicode evasion path traversal" },
    { path: "/api/users/1'OR'1'='1", label: "SQL injection in path" },
    { path: "/api/users/${7*7}", label: "template injection in path" },
    { path: "/admin**************************************************************************",
      label: "wildcard in path" },
  ];

  for (const { path, label } of specialPaths) {
    const fuzzUrl = `${parsed.protocol}//${parsed.host}${path}`;
    const resp = await sendRawRequest(fuzzUrl, "GET", {});
    if (resp) {
      const leaked = checkForInfoLeak(resp.body);
      if (leaked) {
        findings.push({
          severity: "medium",
          category: "Error Handling",
          title: `Information leak via ${label}`,
          description: `Sending a request with ${label} triggers an error response that leaks ${leaked.type} information: ${leaked.summary}`,
          evidence: truncate(leaked.evidence, 500),
          remediation: "Implement a generic error handler. Validate and sanitize all URL paths before processing.",
          cvssScore: 5.3,
          affectedUrl: fuzzUrl,
        });
      }

      // Also check for 500 errors that differ from the baseline
      if (resp.statusCode === 500) {
        findings.push({
          severity: "low",
          category: "Error Handling",
          title: `Unhandled error for ${label}`,
          description: `The server returned a 500 Internal Server Error for ${label}. While no sensitive information was detected in the response, unhandled exceptions may indicate deeper issues.`,
          evidence: `HTTP 500 for ${path}`,
          remediation: "Add input validation and a global error handler to catch malformed requests gracefully.",
          cvssScore: 2.4,
          affectedUrl: fuzzUrl,
        });
      }
    }
  }

  // ---- 3. Malformed / unusual HTTP methods ----
  const methods = ["JEFF", "CATS", "PROPFIND", "TRACE", "TRACK", "DEBUG"];
  for (const method of methods) {
    const resp = await sendRawRequest(targetUrl, method, {});
    if (resp) {
      const leaked = checkForInfoLeak(resp.body);
      if (leaked) {
        findings.push({
          severity: "medium",
          category: "Error Handling",
          title: `Information leak via ${method} method`,
          description: `Sending a ${method} request triggers an error response that leaks ${leaked.type} information: ${leaked.summary}`,
          evidence: truncate(leaked.evidence, 500),
          remediation: "Configure the server to accept only standard HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS). Return 405 Method Not Allowed for others.",
          cvssScore: 4.3,
          affectedUrl: targetUrl,
        });
      }

      // Check for TRACE method enabled (XST)
      if (method === "TRACE" && resp.statusCode === 200) {
        findings.push({
          severity: "medium",
          category: "Error Handling",
          title: "HTTP TRACE method enabled (Cross-Site Tracing)",
          description:
            "The TRACE method is enabled. Combined with XSS, it can be used to steal HttpOnly cookies via Cross-Site Tracing (XST) attacks.",
          evidence: `TRACE returned HTTP 200`,
          remediation: "Disable the TRACE method on the web server.",
          cvssScore: 5.3,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  // ---- 4. Oversized headers ----
  const largeValue = "X".repeat(8192);
  const oversizedHeaders: Record<string, string> = {
    "X-Custom-Header": largeValue,
    "X-Forwarded-For": largeValue,
    "Referer": largeValue,
    "Cookie": `session=${largeValue}`,
  };

  for (const [headerName, headerValue] of Object.entries(oversizedHeaders)) {
    const resp = await sendRawRequest(targetUrl, "GET", { [headerName]: headerValue });
    if (resp) {
      const leaked = checkForInfoLeak(resp.body);
      if (leaked) {
        findings.push({
          severity: "medium",
          category: "Error Handling",
          title: `Information leak via oversized ${headerName} header`,
          description: `Sending an oversized ${headerName} header (${headerValue.length} bytes) triggers an error response that leaks ${leaked.type} information: ${leaked.summary}`,
          evidence: truncate(leaked.evidence, 500),
          remediation: `Limit the size of the ${headerName} header at the reverse proxy level. Ensure error responses do not include internal details.`,
          cvssScore: 4.3,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  // ---- 5. Malformed content-type ----
  const contentTypeTests = [
    { header: { "Content-Type": "application/json" }, body: "{not valid json!!!###" },
    { header: { "Content-Type": "application/xml" }, body: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>" },
    { header: { "Content-Type": "text/xml" }, body: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" },
  ];

  for (const test of contentTypeTests) {
    const resp = await sendRawRequest(targetUrl, "POST", test.header, test.body);
    if (resp) {
      const leaked = checkForInfoLeak(resp.body);
      if (leaked) {
        findings.push({
          severity: "high",
          category: "Error Handling",
          title: "Information leak via malformed request body",
          description: `Sending a malformed body with Content-Type ${test.header["Content-Type"]} triggers an error response that leaks ${leaked.type} information: ${leaked.summary}`,
          evidence: truncate(leaked.evidence, 500),
          remediation: "Validate and parse request bodies safely. Disable external entity processing for XML. Return generic error responses.",
          cvssScore: 6.5,
          affectedUrl: targetUrl,
        });
      }

      // Check for XXE indicators
      if (resp.body && (resp.body.includes("root:") || resp.body.includes("/bin/bash"))) {
        findings.push({
          severity: "critical",
          category: "Error Handling",
          title: "Potential XXE vulnerability",
          description: "The server appears to process XML external entities, as the response contains content from the filesystem (/etc/passwd).",
          evidence: truncate(resp.body.substring(0, 300), 300),
          remediation: "Disable external entity processing in your XML parser. Use JSON instead of XML where possible.",
          cvssScore: 9.8,
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
  body: string;
  headers: http.IncomingHttpHeaders;
}

interface LeakInfo {
  type: string;
  summary: string;
  evidence: string;
}

function checkForInfoLeak(body: string): LeakInfo | null {
  if (!body) return null;

  // Stack trace patterns
  const tracePatterns: Array<{ pattern: RegExp; type: string; summary: string }> = [
    {
      pattern: /at\s+[\w.$]+\s+\([^)]*\.(js|ts|mjs):?\d+:\d+\)/,
      type: "stack trace (Node.js)",
      summary: "a Node.js stack trace revealing file paths and line numbers",
    },
    {
      pattern: /Traceback\s*\(most recent call last\)/,
      type: "stack trace (Python)",
      summary: "a Python traceback revealing module paths and line numbers",
    },
    {
      pattern: /(?:java|javax)\.[\w.]+Exception/,
      type: "stack trace (Java)",
      summary: "a Java exception revealing class names and package structure",
    },
    {
      pattern: /System\.[\w.]+Exception/,
      type: "stack trace (.NET)",
      summary: "a .NET exception revealing class structure",
    },
    {
      pattern: /PHP (?:Fatal error|Warning|Notice):/,
      type: "PHP error",
      summary: "a PHP error message revealing file paths",
    },
    {
      pattern: /in\s+\/[\w./]+\.(?:php|py|rb|java|cs)\s+on\s+line\s+\d+/,
      type: "file path",
      summary: "a server-side file path",
    },
    {
      pattern: /\/(?:home|var|usr|etc|opt|app|srv)\/[\w./]+\.(?:php|py|rb|js|ts|java|conf)/,
      type: "file path",
      summary: "a server-side file path in the error output",
    },
    {
      pattern: /(?:mysql|postgresql|sqlite|mongodb|sqlserver).*error/i,
      type: "database error",
      summary: "a database error message revealing query structure or connection info",
    },
    {
      pattern: /SQLSTATE\[\w+\]/,
      type: "database error",
      summary: "a SQL error state revealing database type and query information",
    },
    {
      pattern: /(?:connection|connect)\s+(?:to\s+)?(?:database|server|host)\s+.*(?:failed|refused|error)/i,
      type: "connection error",
      summary: "a connection error revealing database or service host information",
    },
    {
      pattern: /(?:config|configuration|environment|\.env)/i,
      type: "configuration",
      summary: "configuration or environment details in the error output",
    },
    {
      pattern: /(?:password|secret|api.?key|token|credential)/i,
      type: "sensitive data",
      summary: "potential sensitive data (passwords, API keys) in the error output",
    },
  ];

  for (const { pattern, type, summary } of tracePatterns) {
    const match = body.match(pattern);
    if (match) {
      return {
        type,
        summary,
        evidence: body.substring(0, 500),
      };
    }
  }

  return null;
}

function sendRawRequest(
  url: string,
  method: string,
  extraHeaders: Record<string, string>,
  body?: string
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
        Accept: "*/*",
        ...extraHeaders,
      },
      timeout: 8000,
    };

    if (body) {
      (options.headers as Record<string, string>)["Content-Length"] = Buffer.byteLength(body).toString();
    }

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer | string) => {
        if (typeof chunk === "string") chunks.push(Buffer.from(chunk));
        else chunks.push(chunk);
      });
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode || 0,
          body: Buffer.concat(chunks).toString("utf8"),
          headers: res.headers,
        });
      });
    });

    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });

    if (body) req.write(body);
    req.end();
  });
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.substring(0, maxLen) + "...";
}
