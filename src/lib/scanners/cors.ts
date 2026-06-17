import type { ScannerModule, VulnerabilityResult } from "./types";
import { scannerRequest } from "./http";

/**
 * Test CORS configuration by sending OPTIONS preflight requests with various Origin headers:
 *  - null origin
 *  - Arbitrary evil domain (e.g., https://evil.com)
 *  - Subdomain variants
 * Check for:
 *  - Access-Control-Allow-Origin: * with credentials (ACAO + ACAC)
 *  - Origin reflection without proper validation
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  const parsed = new URL(targetUrl);
  const testOrigins: Array<{ origin: string; label: string }> = [
    { origin: "null", label: "null origin" },
    { origin: "https://evil.com", label: "unrelated domain (evil.com)" },
    { origin: "https://attacker.com", label: "unrelated domain (attacker.com)" },
    { origin: `https://evil.${parsed.hostname}`, label: "evil subdomain" },
    { origin: `https://${parsed.hostname}.evil.com`, label: "parent domain of attacker" },
    { origin: `${parsed.protocol}//${parsed.host}`, label: "same origin (positive control)" },
  ];

  let hasWildcardWithCredentials = false;
  let hasOriginReflection = false;
  const reflectedOrigins: string[] = [];

  for (const { origin, label } of testOrigins) {
    const resp = await sendOptions(targetUrl, origin);
    if (!resp) continue;

    const headers = resp;
    const acao = headers["access-control-allow-origin"];
    const acac = headers["access-control-allow-credentials"];

    // Check for ACAO: * with ACAC: true — this is a misconfiguration
    if (acao === "*" && acac === "true" && !hasWildcardWithCredentials) {
      hasWildcardWithCredentials = true;
      findings.push({
        severity: "critical",
        category: "CORS",
        title: "CORS allows any origin with credentials",
        description:
          "The server responds with `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`. This is a misconfiguration that browsers block by spec, but indicates a serious server-side issue. Some older or non-browser clients may not enforce this restriction.",
        evidence: `Origin: ${origin} -> ACAO: ${acao}, ACAC: ${acac}`,
        remediation:
          "Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Instead, explicitly whitelist trusted origins.",
        cvssScore: 9.1,
        affectedUrl: targetUrl,
      });
    }

    // Check for origin reflection: server reflects the arbitrary origin back
    if (
      acao === origin &&
      origin !== `${parsed.protocol}//${parsed.host}` && // not same-origin
      !hasOriginReflection
    ) {
      reflectedOrigins.push(origin);

      findings.push({
        severity: "high",
        category: "CORS",
        title: `CORS reflects arbitrary ${label}`,
        description: `The server reflects the request Origin header (${origin}) in Access-Control-Allow-Origin without validation. An attacker-controlled page at that origin can make authenticated cross-origin requests, reading sensitive data from the target.`,
        evidence: `Origin: ${origin} -> ACAO: ${acao}, ACAC: ${acac || "not set"}`,
        remediation:
          "Validate the Origin header against an explicit whitelist of trusted domains. Never reflect arbitrary origins in ACAO, especially when credentials are allowed.",
        cvssScore: 8.1,
        affectedUrl: targetUrl,
      });

      hasOriginReflection = true;
    }

    // Check for partial match / subdomain reflection without credentials
    if (
      acao === origin &&
      acac !== "true" &&
      origin !== `${parsed.protocol}//${parsed.host}` &&
      !hasOriginReflection
    ) {
      findings.push({
        severity: "medium",
        category: "CORS",
        title: `CORS reflects ${label} without credentials`,
        description: `The server reflects the Origin header but does not allow credentials. While less severe, this still allows an attacker to read non-credentialed responses cross-origin.`,
        evidence: `Origin: ${origin} -> ACAO: ${acao}`,
        remediation:
          "Validate the Origin header against a whitelist. Only reflect trusted origins.",
        cvssScore: 5.3,
        affectedUrl: targetUrl,
      });
    }
  }

  // Check for overly permissive ACAO: * without ACAC (still worth noting)
  if (!hasWildcardWithCredentials) {
    const defaultResp = await sendOptions(targetUrl, "https://evil.com");
    if (defaultResp) {
      const headers = defaultResp;
      const acao = headers["access-control-allow-origin"];
      if (acao === "*") {
        findings.push({
          severity: "low",
          category: "CORS",
          title: "CORS allows any origin (no credentials)",
          description:
            "The server responds with `Access-Control-Allow-Origin: *`. While credentials are not allowed, any origin can read public resources cross-origin. Verify this is intentional for public APIs.",
          evidence: "ACAO: *",
          remediation:
            "If this is a public API, this may be acceptable. Otherwise, restrict ACAO to specific trusted origins.",
          cvssScore: 2.0,
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

async function sendOptions(
  targetUrl: string,
  origin: string
): Promise<Record<string, string> | null> {
  const res = await scannerRequest(targetUrl, {
    method: "OPTIONS",
    headers: {
      Origin: origin,
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Headers": "Content-Type, Authorization",
    },
    followRedirects: false,
    timeoutMs: 8000,
  });
  return res ? res.headers : null;
}
