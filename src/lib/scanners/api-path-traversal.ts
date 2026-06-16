import type { ScannerModule, VulnerabilityResult } from "./types";
import { fetchBody as httpGetBody } from "./http";

const PATH_TRAVERSAL_PAYLOADS = [
  { param: "file", value: "../../../etc/passwd" },
  { param: "path", value: "..\\..\\..\\windows\\win.ini" },
  { param: "file", value: "../../../etc/passwd%00" },
  { param: "file", value: "....//....//....//etc/passwd" },
  { param: "path", value: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd" },
  { param: "file", value: "..%252f..%252f..%252fetc/passwd" },
  { param: "file", value: "/etc/passwd" },
  { param: "template", value: "../../../etc/passwd" },
  { param: "document", value: "../../../etc/passwd" },
  { param: "page", value: "....//....//....//etc/passwd" },
];

const FS_INDICATORS = [
  "root:", "nobody:", "daemon:", "bin:", "sys:", "[extensions]",
  "; for 16-bit", "root", "bin/bash", "/bin/sh", "nologin",
  "www-data", "postgres:", "ssh-dss", "ssh-rsa",
];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  for (const payload of PATH_TRAVERSAL_PAYLOADS) {
    const testUrl = appendQueryParam(targetUrl, payload.param, payload.value);
    const resp = await httpGetBody(testUrl);
    if (!resp) continue;

    const body = resp.body.toLowerCase();
    const matchedIndicator = FS_INDICATORS.find((ind) => body.includes(ind));

    if (matchedIndicator) {
      findings.push({
        severity: "critical",
        category: "Path Traversal",
        title: `Path traversal via "${payload.param}" parameter`,
        description: `The API endpoint exposed file contents when probed with traversal payload "${payload.value}". The response contained "${matchedIndicator}", confirming filesystem access.`,
        evidence: `Endpoint returned system file content when accessing with: ${testUrl}\n\nResponse excerpt: ${resp.body.slice(0, 500)}`,
        remediation: "Validate and sanitize all file path inputs. Use an allowlist of permitted files/directories. Avoid passing user input directly to filesystem operations. Use a mapping table instead of direct file paths.",
        cvssScore: 9.5,
        affectedUrl: testUrl,
      });
    }

    if (resp.statusCode === 200 && payload.value.includes("etc/passwd") && body.length > 100) {
      findings.push({
        severity: "high",
        category: "Path Traversal",
        title: `Potential path traversal via "${payload.param}" (status 200 with large body)`,
        description: `The API returned status 200 with a response body of ${resp.body.length} bytes when accessing paths with traversal sequences. This is a strong indicator of path traversal vulnerability.`,
        evidence: `Path traversal to "${payload.value}" returned ${resp.body.length} bytes\n\nResponse: ${resp.body.slice(0, 300)}`,
        remediation: "Implement strict input validation for file paths. Use a whitelist approach and avoid direct filesystem access from user input.",
        cvssScore: 8.0,
        affectedUrl: testUrl,
      });
    }
  }

  return findings;
};

function appendQueryParam(baseUrl: string, name: string, value: string): string {
  const parsed = new URL(baseUrl);
  parsed.searchParams.set(name, value);
  return parsed.toString();
}

// httpGetBody is provided by ./http (SSRF-safe).
