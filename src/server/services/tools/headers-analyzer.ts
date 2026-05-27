import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";
import { fetchHeaders } from "@/lib/scanners/headers";

interface HeaderFinding {
  header: string;
  status: "present" | "missing" | "weak";
  value: string | null;
  recommendation: string;
}

interface HeaderAnalysisResult {
  score: number;
  targetUrl: string;
  findings: HeaderFinding[];
  missingHeaders: string[];
  aiRecommendations: string;
}

const RECOMMENDED_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
];


export async function analyzeHeaders(targetUrl: string): Promise<HeaderAnalysisResult> {
  const headers = await fetchHeaders(targetUrl);

  if (!headers) {
    return {
      score: 0,
      targetUrl,
      findings: [],
      missingHeaders: [],
      aiRecommendations: "Failed to reach the target URL. Please verify the URL is correct and the server is reachable.",
    };
  }

  const findings: HeaderFinding[] = [];
  const missingHeaders: string[] = [];

  for (const header of RECOMMENDED_HEADERS) {
    const rawValue = headers[header];
    const value = Array.isArray(rawValue) ? rawValue[0] : rawValue;

    if (!value) {
      findings.push({
        header,
        status: "missing",
        value: null,
        recommendation: getDefaultRecommendation(header),
      });
      missingHeaders.push(header);
    } else if (header === "strict-transport-security") {
      const maxAgeMatch = value.match(/max-age=(\d+)/);
      if (maxAgeMatch && parseInt(maxAgeMatch[1], 10) < 2592000) {
        findings.push({ header, status: "weak", value, recommendation: "Increase max-age to at least 31536000 (1 year) and add includeSubDomains" });
      } else {
        findings.push({ header, status: "present", value, recommendation: "Configured correctly" });
      }
    } else if (header === "content-security-policy" && (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'"))) {
      findings.push({ header, status: "weak", value, recommendation: "Remove 'unsafe-inline' and 'unsafe-eval' directives. Use nonce-based CSP instead." });
    } else {
      findings.push({ header, status: "present", value, recommendation: "Configured correctly" });
    }
  }

  const presentCount = findings.filter((f) => f.status === "present").length;
  const weakCount = findings.filter((f) => f.status === "weak").length;
  const score = Math.max(0, Math.min(100, Math.round((presentCount / RECOMMENDED_HEADERS.length) * 100) + (weakCount > 0 ? -10 : 0)));

  const headersJson = JSON.stringify(Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k, Array.isArray(v) ? v[0] : v])
  ));

  const systemPrompt = `You are a security engineer specializing in web security headers. Analyze the HTTP security headers and provide recommendations. Return a JSON object with:
- aiRecommendations: string (detailed recommendations for improving the security header configuration)

Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

  try {
  const response = await callClaude(
    [{ role: "user", content: "Analyze these HTTP security headers and provide recommendations:\n\nURL: " + targetUrl + "\n\nHeaders:\n" + headersJson + "\n\nFindings:\n" + JSON.stringify(findings, null, 2) }],
    { system: systemPrompt, maxTokens: 2048 }
  );

    const aiResult = JSON.parse(response) as { aiRecommendations: string };
    if (typeof aiResult.aiRecommendations !== "string") {
      throw new Error("Invalid response structure from AI");
    }
    logger.info("HeadersAnalyzer", "Score: " + score + " for " + targetUrl);
    return { score, targetUrl, findings, missingHeaders, aiRecommendations: aiResult.aiRecommendations };
  } catch {
    logger.error("HeadersAnalyzer", "Failed to parse AI recommendations");
    return { score, targetUrl, findings, missingHeaders, aiRecommendations: "AI analysis unavailable." };
  }
}

function getDefaultRecommendation(header: string): string {
  const recommendations: Record<string, string> = {
    "strict-transport-security": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "content-security-policy": "Add: Content-Security-Policy: default-src 'self'",
    "x-frame-options": "Add: X-Frame-Options: DENY",
    "x-content-type-options": "Add: X-Content-Type-Options: nosniff",
    "referrer-policy": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    "permissions-policy": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
  };
  return recommendations[header] || "Add this security header";
}
