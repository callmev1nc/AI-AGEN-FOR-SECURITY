import type { ScannerModule, VulnerabilityResult } from "./types";
import { scannerRequest } from "./http";

const AUTH_TESTS: Array<{
  name: string;
  headers: Record<string, string>;
  severity: "critical" | "high" | "medium" | "low" | "info";
}> = [
  {
    name: "Missing Auth Headers",
    headers: {},
    severity: "high",
  },
  {
    name: "Empty Bearer Token",
    headers: { Authorization: "Bearer " },
    severity: "high",
  },
  {
    name: "Invalid Bearer Token",
    headers: { Authorization: "Bearer invalid-token-12345" },
    severity: "medium",
  },
  {
    name: "Expired JWT Format",
    headers: { Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ" },
    severity: "medium",
  },
  {
    name: "JWT with alg: none",
    headers: { Authorization: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0." },
    severity: "critical",
  },
  {
    name: "Basic Auth w/ admin:admin",
    headers: { Authorization: "Basic " + Buffer.from("admin:admin").toString("base64") },
    severity: "high",
  },
  {
    name: "Role Escalation Attempt",
    headers: { "X-Role": "admin", "X-User-Role": "administrator" },
    severity: "high",
  },
  {
    name: "IDOR via Path",
    headers: { "X-User-Id": "admin" },
    severity: "medium",
  },
];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const baseResp = await httpGet(targetUrl, {});
  const baseStatus = baseResp?.statusCode ?? 0;

  for (const test of AUTH_TESTS) {
    if (test.name === "Missing Auth Headers") continue; // identical to baseline
    const resp = await httpGet(targetUrl, test.headers);
    if (!resp) continue;

    if (resp.statusCode === 200 && baseStatus !== 200) {
      findings.push({
        severity: test.severity,
        category: "Authentication Bypass",
        title: `Auth bypass: ${test.name}`,
        description: `The endpoint returned 200 OK with "${test.name}" whereas the baseline request returned ${baseStatus}. This indicates the authorization check is insufficient.`,
        evidence: `Baseline: ${baseStatus} | Test headers: ${JSON.stringify(test.headers)} -> ${resp.statusCode}\n\nResponse: ${resp.body.slice(0, 300)}`,
        remediation: "Implement consistent authorization checks for all endpoints. Use middleware-based auth that cannot be bypassed. Validate JWT signatures properly. Never trust user-supplied role headers.",
        cvssScore: test.severity === "critical" ? 9.5 : test.severity === "high" ? 8.0 : 5.0,
        affectedUrl: targetUrl,
      });
    }

    if (resp.statusCode === 403 || resp.statusCode === 401) {
      if (test.headers.Authorization === "Bearer invalid-token-12345" || test.name.includes("Basic Auth")) {
        const body = resp.body.toLowerCase();
        if (body.includes("invalid") || body.includes("expired") || body.includes("unauthorized")) {
          if (!findings.some((f) => f.title.includes(test.name))) {
            findings.push({
              severity: "low",
              category: "Authentication Bypass",
              title: `Auth properly enforced: ${test.name}`,
              description: "The endpoint correctly rejected invalid credentials with a proper error response.",
              evidence: `Response: ${resp.body.slice(0, 200)}`,
              remediation: "No action needed. Authentication is properly enforced for this test.",
              cvssScore: 0,
              affectedUrl: targetUrl,
            });
          }
        }
      }
    }

    if (resp.statusCode === 500) {
      findings.push({
        severity: "medium",
        category: "Authentication Bypass",
        title: `Auth endpoint error: ${test.name}`,
        description: "The endpoint returned a 500 Internal Server Error when probed with auth manipulation headers. This may indicate improper error handling.",
        evidence: `Test: ${test.name}\nHeaders: ${JSON.stringify(test.headers)}\nResponse: ${resp.body.slice(0, 200)}`,
        remediation: "Implement proper error handling for all authentication scenarios. Return generic error messages and avoid stack traces in production.",
        cvssScore: 4.5,
        affectedUrl: targetUrl,
      });
    }
  }

  return findings;
};

async function httpGet(
  url: string,
  headers: Record<string, string>
): Promise<{ statusCode: number; body: string } | null> {
  const res = await scannerRequest(url, {
    method: "GET",
    headers,
    followRedirects: false,
    timeoutMs: 10000,
  });
  if (!res) return null;
  return { statusCode: res.statusCode, body: res.body };
}
