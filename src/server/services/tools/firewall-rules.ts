import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";

interface FirewallRule {
  rule: string;
  description: string;
  riskLevel: "low" | "medium" | "high";
}

interface FirewallRulesResult {
  rules: FirewallRule[];
  explanation: string;
  warnings: string[];
}

const PLATFORM_DESCRIPTIONS: Record<string, string> = {
  iptables: "Linux iptables rules (IPv4)",
  ufw: "UFW (Uncomplicated Firewall) commands",
  aws: "AWS Security Group rules (JSON/CLI format)",
};

export async function generateFirewallRules(
  description: string,
  platform: string
): Promise<FirewallRulesResult> {
  const systemPrompt = `You are a network security engineer. Generate firewall rules based on natural language descriptions.
Return a JSON object with:
- rules: array of { rule: string, description: string, riskLevel: "low" | "medium" | "high" }
- explanation: string (brief explanation of the approach)
- warnings: string[] (security warnings or caveats)

Generate rules for ${PLATFORM_DESCRIPTIONS[platform] || platform}.
Rules should follow best practices (least privilege, default deny, etc.).
Add comments explaining each rule.
Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

  try {
  const response = await callClaude(
    [{ role: "user", content: `Generate firewall rules for this requirement:\n\n${description}` }],
    { system: systemPrompt, maxTokens: 3072 }
  );

    const result = JSON.parse(response) as FirewallRulesResult;
    if (!Array.isArray(result.rules) || typeof result.explanation !== "string") {
      throw new Error("Invalid response structure from AI");
    }
    logger.info("FirewallRules", `Generated ${result.rules.length} rules for ${platform}`);
    return result;
  } catch {
    logger.error("FirewallRules", "Failed to parse Claude response as JSON");
    return {
      rules: [],
      explanation: "Failed to generate firewall rules. Please try rephrasing your description.",
      warnings: ["Rule generation error"],
    };
  }
}
