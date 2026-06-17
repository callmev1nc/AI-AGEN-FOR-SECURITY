import type { ScannerModule, VulnerabilityResult } from "./types";
import { getHeader } from "./types";
import { scannerRequest } from "./http";

/**
 * Check for information disclosure:
 *  - Server header leaking version details
 *  - X-Powered-By header
 *  - Stack traces in error responses
 *  - Directory listing enabled
 *  - Common debug/sensitive endpoints (/.env, /phpinfo, /debug, etc.)
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  // ---- 1. Check response headers for info leakage ----
  const mainResponse = await httpGet(targetUrl);
  if (mainResponse) {
    const serverHeader = getHeader(mainResponse.headers as unknown as Record<string, unknown>, "server");
    if (serverHeader && hasVersionInfo(serverHeader)) {
      findings.push({
        severity: "medium",
        category: "Information Disclosure",
        title: "Server header reveals version information",
        description: `The Server header discloses detailed version information: "${serverHeader}". Attackers can use this to look up known vulnerabilities for the exact software version.`,
        evidence: `Server: ${serverHeader}`,
        remediation: "Configure the web server to omit version details from the Server header, or remove the header entirely.",
        cvssScore: 5.3,
        affectedUrl: targetUrl,
      });
    }

    const xPoweredBy = getHeader(mainResponse.headers as unknown as Record<string, unknown>, "x-powered-by");
    if (xPoweredBy) {
      findings.push({
        severity: "low",
        category: "Information Disclosure",
        title: "X-Powered-By header exposes technology stack",
        description: `The X-Powered-By header reveals: "${xPoweredBy}". This information helps attackers fingerprint the technology stack and identify potential vulnerabilities.`,
        evidence: `X-Powered-By: ${xPoweredBy}`,
        remediation: "Remove or disable the X-Powered-By header in your application server configuration.",
        cvssScore: 3.1,
        affectedUrl: targetUrl,
      });
    }

    // ---- 2. Check for stack traces in the main response ----
    if (mainResponse.body) {
      const tracePatterns = [
        /at\s+[\w.]+\s+\([^)]*\.js:\d+:\d+\)/,      // Node.js stack trace
        /at\s+[\w.]+\s+\([^)]*\.php[^)]*\)/,          // PHP stack trace
        /Traceback\s*\(most recent call last\)/,       // Python
        /Exception\s+[\w.]+:\s*.+at\s+[\w.]+/,        // Java
        /System\.[\w.]+Exception/,                      // .NET
        /in\s+\/[\w./]+\.(?:php|py|rb|java|cs)\s+line\s+\d+/, // Generic file+line
      ];

      for (const pattern of tracePatterns) {
        if (pattern.test(mainResponse.body)) {
          const snippet = extractSnippet(mainResponse.body, pattern);
          findings.push({
            severity: "medium",
            category: "Information Disclosure",
            title: "Stack trace exposed in response body",
            description: "The server returned a stack trace in the response body. Stack traces can reveal internal file paths, library versions, and application logic, aiding an attacker in crafting targeted exploits.",
            evidence: snippet,
            remediation: "Configure the application to return generic error pages in production. Ensure debug mode is disabled.",
            cvssScore: 5.3,
            affectedUrl: targetUrl,
          });
          break; // one stack-trace finding is enough
        }
      }
    }
  }

  // ---- 3. Check for directory listing ----
  const dirPaths = ["/uploads/", "/static/", "/assets/", "/files/", "/images/"];
  for (const dirPath of dirPaths) {
    const dirUrl = buildUrl(targetUrl, dirPath);
    const dirResp = await httpGet(dirUrl);
    if (dirResp && dirResp.statusCode === 200 && isDirectoryListing(dirResp.body || "")) {
      findings.push({
        severity: "medium",
        category: "Information Disclosure",
        title: `Directory listing enabled at ${dirPath}`,
        description: `The server returns a directory listing for ${dirPath}. This exposes the file structure and allows attackers to discover hidden files and directories.`,
        evidence: `Directory listing detected at ${dirUrl}`,
        remediation: "Disable directory listing on the web server. For Apache, use `Options -Indexes`. For Nginx, remove `autoindex on`.",
        cvssScore: 5.3,
        affectedUrl: dirUrl,
      });
    }
  }

  // ---- 4. Check common sensitive endpoints ----
  const sensitivePaths = [
    { path: "/.env", name: ".env file", severity: "critical" as const, desc: "Environment file exposed" },
    { path: "/.git/config", name: "Git config", severity: "critical" as const, desc: "Git repository configuration exposed" },
    { path: "/.git/HEAD", name: "Git HEAD", severity: "critical" as const, desc: "Git repository HEAD file exposed" },
    { path: "/.htaccess", name: ".htaccess", severity: "medium" as const, desc: "Apache configuration file exposed" },
    { path: "/wp-config.php", name: "WordPress config", severity: "critical" as const, desc: "WordPress configuration file exposed" },
    { path: "/phpinfo.php", name: "phpinfo()", severity: "high" as const, desc: "PHP information page exposed" },
    { path: "/server-status", name: "Apache server-status", severity: "medium" as const, desc: "Apache server status page accessible" },
    { path: "/server-info", name: "Apache server-info", severity: "medium" as const, desc: "Apache server info page accessible" },
    { path: "/debug", name: "Debug endpoint", severity: "high" as const, desc: "Debug endpoint accessible" },
    { path: "/debug/vars", name: "Debug vars", severity: "high" as const, desc: "Debug variables endpoint accessible" },
    { path: "/actuator", name: "Spring Actuator", severity: "high" as const, desc: "Spring Boot Actuator endpoint accessible" },
    { path: "/actuator/health", name: "Actuator health", severity: "low" as const, desc: "Spring Boot health endpoint accessible" },
    { path: "/trace", name: "Trace endpoint", severity: "medium" as const, desc: "Trace/debug endpoint accessible" },
    { path: "/console", name: "Console", severity: "high" as const, desc: "Web console or debugger accessible" },
    { path: "/graphql", name: "GraphQL", severity: "info" as const, desc: "GraphQL endpoint discovered" },
    { path: "/api-docs", name: "API docs", severity: "low" as const, desc: "API documentation accessible" },
    { path: "/swagger-ui.html", name: "Swagger UI", severity: "low" as const, desc: "Swagger UI accessible" },
    { path: "/robots.txt", name: "robots.txt", severity: "info" as const, desc: "robots.txt may reveal hidden paths" },
    { path: "/sitemap.xml", name: "sitemap.xml", severity: "info" as const, desc: "Sitemap reveals site structure" },
    { path: "/.DS_Store", name: ".DS_Store", severity: "medium" as const, desc: "macOS directory metadata file exposed" },
    { path: "/web.config", name: "web.config", severity: "medium" as const, desc: "IIS configuration file exposed" },
    { path: "/backup.sql", name: "SQL backup", severity: "critical" as const, desc: "Database backup file exposed" },
    { path: "/database.sql", name: "SQL database", severity: "critical" as const, desc: "Database dump file exposed" },
  ];

  for (const entry of sensitivePaths) {
    const checkUrl = buildUrl(targetUrl, entry.path);
    const resp = await httpGet(checkUrl);
    if (resp && resp.statusCode === 200 && resp.body && resp.body.length > 0) {
      // Filter out generic 200 error pages that are catch-all routes
      const bodyLen = resp.body.length;
      const isLikelyReal = bodyLen > 50 && bodyLen < 5000000; // reasonable response size

      if (isLikelyReal) {
        // Extra check: for .env, make sure it looks like env content
        if (entry.path === "/.env" && !looksLikeEnvFile(resp.body)) continue;
        // For .git/config, check for [core] section
        if (entry.path === "/.git/config" && !resp.body.includes("[core]")) continue;
        // For .git/HEAD, check for ref: prefix
        if (entry.path === "/.git/HEAD" && !resp.body.startsWith("ref:")) continue;

        findings.push({
          severity: entry.severity,
          category: "Information Disclosure",
          title: `${entry.desc}: ${entry.name}`,
          description: `A sensitive resource was found at ${entry.path}. This endpoint may expose internal configuration, credentials, or application internals.`,
          evidence: `HTTP ${resp.statusCode} — ${resp.body.substring(0, 200)}`,
          remediation: `Restrict access to ${entry.path}. Remove the file if it is not needed, or add authentication/authorization requirements.`,
          cvssScore: severityToCvss(entry.severity),
          affectedUrl: checkUrl,
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
  headers: Record<string, string>;
  body: string | null;
}

async function httpGet(url: string): Promise<HttpResponse | null> {
  const res = await scannerRequest(url, {
    method: "GET",
    headers: { Accept: "*/*" },
    followRedirects: false,
    timeoutMs: 8000,
  });
  if (!res) return null;
  return { statusCode: res.statusCode, headers: res.headers, body: res.body };
}

function hasVersionInfo(serverHeader: string): boolean {
  // Look for digits after a slash, e.g. "nginx/1.18.0" or "Apache/2.4.41"
  return /\d+\.\d+/.test(serverHeader);
}

function isDirectoryListing(body: string): boolean {
  const indicators = [
    /Index of\s+\/.+/,
    /Directory listing for\s+\/.+/,
    /<title>.*Index of.*<\/title>/i,
    /Parent Directory/,
    /<a href="[^"]*">[^<]*<\/a>\s+\d+\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}/, // Apache-style listing
  ];
  return indicators.some((p) => p.test(body));
}

function looksLikeEnvFile(body: string): boolean {
  const lines = body.split("\n").filter((l) => l.trim().length > 0);
  let envLineCount = 0;
  for (const line of lines) {
    if (/^[A-Z_][A-Z0-9_]*=/.test(line.trim())) envLineCount++;
  }
  return envLineCount >= 2; // At least 2 KEY=VALUE lines
}

function buildUrl(base: string, path: string): string {
  const parsed = new URL(base);
  return `${parsed.protocol}//${parsed.host}${path}`;
}

function extractSnippet(body: string, pattern: RegExp): string {
  const match = body.match(pattern);
  if (match && match.index !== undefined) {
    const start = Math.max(0, match.index - 20);
    const end = Math.min(body.length, match.index + match[0].length + 100);
    return body.substring(start, end);
  }
  return body.substring(0, 300);
}

function severityToCvss(severity: string): number {
  const map: Record<string, number> = {
    critical: 9.1,
    high: 7.5,
    medium: 5.3,
    low: 3.1,
    info: 0.0,
  };
  return map[severity] ?? 0.0;
}
