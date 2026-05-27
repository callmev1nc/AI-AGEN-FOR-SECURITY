import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";

interface PayloadItem {
  payload: string;
  type: string;
  riskLevel: "low" | "medium" | "high";
  description: string;
}

interface PayloadGeneratorResult {
  payloads: PayloadItem[];
  disclaimer: string;
  warnings: string[];
}

const VULNERABILITY_DESCRIPTIONS: Record<string, string> = {
  "sql-injection": "SQL Injection (classic, blind, time-based, UNION)",
  "xss": "Cross-Site Scripting (reflected, stored, DOM-based)",
  "path-traversal": "Path Traversal (directory traversal, file inclusion)",
  "command-injection": "OS Command Injection",
  "nosql-injection": "NoSQL Injection (MongoDB)",
  "ldap-injection": "LDAP Injection",
  "xxe": "XML External Entity (XXE) Injection",
  "ssrf": "Server-Side Request Forgery (SSRF)",
};

export async function generateEthicalPayloads(
  endpointDescription: string,
  endpointType: string,
  vulnerabilityTypes: string[]
): Promise<PayloadGeneratorResult> {
  const vulnDescriptions = vulnerabilityTypes
    .map((v) => VULNERABILITY_DESCRIPTIONS[v] || v)
    .join(", ");

  const systemPrompt = `You are a security researcher generating ethical test payloads for authorized penetration testing only. Generate realistic test payloads for the specified vulnerability types. Return a JSON object with:
- payloads: array of { payload: string, type: string, riskLevel: "low" | "medium" | "high", description: string }
- disclaimer: string (legal disclaimer)
- warnings: string[] (important warnings about using these payloads)

Each payload must be clearly labeled with its type and risk level.
Include encoding variations (URL-encoded, double-encoded, etc.) where applicable.
Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

  try {
  const response = await callClaude(
    [{ role: "user", content: "Generate ethical test payloads for:\n\nEndpoint: " + endpointDescription + "\nType: " + endpointType + "\nVulnerabilities: " + vulnDescriptions }],
    { system: systemPrompt, maxTokens: 4096 }
  );

    const result = JSON.parse(response) as PayloadGeneratorResult;
    if (!Array.isArray(result.payloads) || typeof result.disclaimer !== "string") {
      throw new Error("Invalid response structure from AI");
    }
    logger.info("PayloadGenerator", "Generated " + result.payloads.length + " payloads for " + vulnerabilityTypes.length + " types");
    return result;
  } catch {
    logger.error("PayloadGenerator", "Failed to parse Claude response as JSON");
    return {
      payloads: [],
      disclaimer: "Failed to generate payloads. Please try again.",
      warnings: ["Generation error occurred"],
    };
  }
}
