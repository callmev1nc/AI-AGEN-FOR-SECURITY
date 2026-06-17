import type { ScannerModule, VulnerabilityResult } from "./types";
import { fetchBody as httpGetBody } from "./http";

const SQL_PAYLOADS = [
  { param: "id", value: "' OR '1'='1" },
  { param: "id", value: "' UNION SELECT NULL,NULL,NULL--" },
  { param: "id", value: "1; DROP TABLE users--" },
  { param: "q", value: "' OR 1=1--" },
  { param: "q", value: "' OR '1'='1' --" },
  { param: "username", value: "admin' --" },
  { param: "password", value: "' OR '1'='1" },
  { param: "id", value: "' WAITFOR DELAY '0:0:5'--" },
  { param: "id", value: "1 AND 1=1" },
  { param: "id", value: "1 AND 1=2" },
];

const SQLI_INDICATORS = [
  "sql", "syntax error", "mysql", "postgresql", "ora-", "sqlite",
  "unclosed quotation", "odbc", "driver", "warning: mysql",
  "you have an error", "pg_", "microsoft ole db",
];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  for (const payload of SQL_PAYLOADS) {
    const testUrl = appendQueryParam(targetUrl, payload.param, payload.value);
    const resp = await httpGetBody(testUrl);
    if (!resp) continue;

    const bodyLower = resp.body.toLowerCase();
    const matchedIndicator = SQLI_INDICATORS.find((ind) => bodyLower.includes(ind));

    if (matchedIndicator) {
      findings.push({
        severity: "critical",
        category: "SQL Injection",
        title: `SQL injection via "${payload.param}" parameter`,
        description: `The API endpoint returned a database error or SQL-related message when probed with payload "${payload.value}". This strongly suggests the input is interpolated into SQL queries without sanitization.`,
        evidence: `Parameter "${payload.param}" with value "${payload.value}" caused response containing "${matchedIndicator}"\n\nResponse: ${resp.body.slice(0, 300)}`,
        remediation: "Use parameterized queries (prepared statements) for all database operations. Never concatenate user input directly into SQL queries. Implement input validation and use an ORM with safe query building.",
        cvssScore: 9.0,
        affectedUrl: testUrl,
      });
    }

    // Blind SQLi: only test when we have the TRUE condition as payload
    if (payload.value === "1 AND 1=1") {
      const baselineUrl = appendQueryParam(targetUrl, payload.param, "1");
      const baseline = await httpGetBody(baselineUrl);
      const falseUrl = appendQueryParam(targetUrl, payload.param, "1 AND 1=2");
      const falseResp = await httpGetBody(falseUrl);
      if (baseline && falseResp) {
        const baselineLen = baseline.body.length;
        const trueLen = resp.body.length;
        const falseLen = falseResp.body.length;
        if (Math.abs(trueLen - baselineLen) < 10 && Math.abs(falseLen - baselineLen) > 10) {
          findings.push({
            severity: "medium",
            category: "SQL Injection",
            title: `Potential blind SQL injection via "${payload.param}"`,
            description: "The API returned different response sizes for boolean conditions (1=1 vs 1=2), which may indicate blind SQL injection vulnerability.",
            evidence: `Response sizes: baseline=${baselineLen}, TRUE(${trueLen}), FALSE(${falseLen}). TRUE matches baseline but FALSE differs significantly.`,
            remediation: "Use parameterized queries. Ensure consistent response sizes regardless of query results.",
            cvssScore: 6.5,
            affectedUrl: testUrl,
          });
        }
      }
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
