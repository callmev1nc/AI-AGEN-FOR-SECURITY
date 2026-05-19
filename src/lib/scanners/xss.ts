import * as http from "http";
import * as https from "https";
import type { ScannerModule, VulnerabilityResult } from "./types";

/**
 * Test for reflected XSS by injecting benign test payloads into URL query
 * parameters and checking if the payload appears unescaped in the response.
 *
 * Payloads are designed to be detectable but never execute:
 *  - <script>secupi-test</script>
 *  - "secupi-test"
 *  - <img src=x onerror=secupi>
 *  - secupi-test<script>
 *  - javascript:secupi-test
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const seen = new Set<string>();

  const payloads: Array<{
    value: string;
    paramName: string;
    context: "html" | "attribute" | "javascript";
  }> = [
    {
      paramName: "q",
      value: '<script>secupi-test</script>',
      context: "html",
    },
    {
      paramName: "q",
      value: '"secupi-test"',
      context: "attribute",
    },
    {
      paramName: "q",
      value: "<img src=x onerror=secupi>",
      context: "html",
    },
    {
      paramName: "q",
      value: "secupi-test<script>",
      context: "html",
    },
    {
      paramName: "search",
      value: '<script>secupi-test</script>',
      context: "html",
    },
    {
      paramName: "search",
      value: '"secupi-test"',
      context: "attribute",
    },
    {
      paramName: "id",
      value: '<script>secupi-test</script>',
      context: "html",
    },
    {
      paramName: "page",
      value: '"secupi-test"',
      context: "attribute",
    },
    {
      paramName: "lang",
      value: '<script>secupi-test</script>',
      context: "html",
    },
    {
      paramName: "callback",
      value: "secupi-test",
      context: "javascript",
    },
  ];

  for (const payload of payloads) {
    const testUrl = appendQueryParam(targetUrl, payload.paramName, payload.value);
    const resp = await httpGetBody(testUrl);

    if (!resp || !resp.body) continue;

    const body = resp.body;

    // Check if the exact payload value appears in the response (reflection)
    if (body.includes(payload.value)) {
      // Verify it is not just part of a URL-encoded query string echo
      // (some frameworks echo back the full URL in comments or meta tags)
      const encodedValue = encodeURIComponent(payload.value);
      const isInUrlEcho =
        body.includes(`=${encodedValue}`) &&
        !body.includes(`>${payload.value}`) &&
        !body.includes(`"${payload.value}`) &&
        !body.includes(`'${payload.value}`);

      if (!isInUrlEcho) {
        const key = `${payload.paramName}:${payload.value}`;
        if (!seen.has(key)) {
          seen.add(key);

          const severity: VulnerabilityResult["severity"] =
            payload.context === "html" ? "high" : "medium";
          const cvss = payload.context === "html" ? 7.5 : 5.3;

          findings.push({
            severity,
            category: "Cross-Site Scripting (XSS)",
            title: `Reflected XSS via "${payload.paramName}" parameter (${payload.context} context)`,
            description: `The value of the "${payload.paramName}" query parameter is reflected unescaped in the response body within a ${payload.context} context. An attacker can craft a malicious URL that injects arbitrary JavaScript into the page when a victim clicks the link.`,
            evidence: `Parameter "${payload.paramName}" with value "${payload.value}" reflected in response body at ${testUrl}`,
            remediation:
              "Encode all user-supplied data on output. Use context-aware encoding (HTML entity encoding for HTML context, attribute encoding for attribute context). Implement Content-Security-Policy as a defense-in-depth measure.",
            cvssScore: cvss,
            affectedUrl: testUrl,
          });
        }
      }
    }

    // Also check for partial reflection (the tag is broken but content appears)
    if (payload.context === "html") {
      const strippedPayload = payload.value.replace(/[<>"]/g, "");
      if (
        strippedPayload.length > 0 &&
        body.includes(strippedPayload) &&
        !body.includes(payload.value) &&
        !seen.has(`partial:${payload.paramName}:${payload.value}`)
      ) {
        // Payload was partially sanitized — tags removed but content kept
        // This is lower risk but may indicate incomplete filtering
        seen.add(`partial:${payload.paramName}:${payload.value}`);
        findings.push({
          severity: "low",
          category: "Cross-Site Scripting (XSS)",
          title: `Partial reflection of "${payload.paramName}" parameter (sanitized but content preserved)`,
          description: `The value of "${payload.paramName}" was partially sanitized (HTML tags removed) but the content "${strippedPayload}" still appears in the response. While the immediate XSS risk is low, incomplete filtering may be bypassable with alternative encodings.`,
          evidence: `Content "${strippedPayload}" from parameter "${payload.paramName}" found in response body`,
          remediation:
            "Implement proper context-aware output encoding. Do not rely on tag stripping alone as it can often be bypassed.",
          cvssScore: 3.1,
          affectedUrl: testUrl,
        });
      }
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface HttpResponse {
  statusCode: number;
  body: string;
}

function appendQueryParam(baseUrl: string, name: string, value: string): string {
  const parsed = new URL(baseUrl);
  parsed.searchParams.set(name, value);
  return parsed.toString();
}

function httpGetBody(url: string): Promise<HttpResponse | null> {
  return new Promise((resolve) => {
    const parsed = new URL(url);
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
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer | string) => {
        if (typeof chunk === "string") chunks.push(Buffer.from(chunk));
        else chunks.push(chunk);
      });
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode || 0,
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
