import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";

interface PolicyIssue {
  category: string;
  finding: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  recommendation: string;
  nistReference: string;
}

interface PasswordPolicyResult {
  complianceScore: number;
  issues: PolicyIssue[];
  strengths: string[];
  overallAssessment: string;
}

export async function auditPasswordPolicy(policyText: string): Promise<PasswordPolicyResult> {
  const systemPrompt = `You are a cybersecurity compliance auditor specializing in NIST SP 800-63B guidelines. Audit the provided password policy against NIST 800-63B. Return a JSON object with:
- complianceScore: number 0-100
- issues: array of { category: string, finding: string, severity: string, recommendation: string, nistReference: string }
- strengths: string[]
- overallAssessment: string

NIST 800-63B key requirements:
- Minimum 8 characters (memorized secrets)
- No composition rules (no required mix of upper/lower/digits/special)
- No periodic change requirements
- Check against breached password lists
- Allow copy/paste during entry
- Allow display of password while typing
- Support passwords up to at least 64 characters

Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

  try {
  const response = await callClaude(
    [{ role: "user", content: "Audit this password policy against NIST 800-63B:\n\n---\n" + policyText + "\n---" }],
    { system: systemPrompt, maxTokens: 3072 }
  );

    const result = JSON.parse(response) as PasswordPolicyResult;
    if (typeof result.complianceScore !== "number" || !Array.isArray(result.issues)) {
      throw new Error("Invalid response structure from AI");
    }
    logger.info("PasswordAuditor", "Compliance score: " + result.complianceScore);
    return result;
  } catch {
    logger.error("PasswordAuditor", "Failed to parse Claude response as JSON");
    return {
      complianceScore: 0,
      issues: [{ category: "Error", finding: "Failed to analyze policy", severity: "medium", recommendation: "Please try again", nistReference: "N/A" }],
      strengths: [],
      overallAssessment: "An error occurred during analysis.",
    };
  }
}
