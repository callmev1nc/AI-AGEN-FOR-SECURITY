import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";

interface PhishingResult {
  score: number;
  verdict: string;
  redFlags: string[];
  suspiciousLinks: string[];
  explanation: string;
}

export async function analyzePhishing(emailText: string): Promise<PhishingResult> {
  const systemPrompt = `You are a cybersecurity expert specializing in phishing detection. Analyze the provided email text and return a JSON object with:
- score: number 0-100 (0 = safe, 100 = definitely phishing)
- verdict: "Safe" | "Suspicious" | "Likely Phishing" | "Confirmed Phishing"
- redFlags: string[] — list of suspicious indicators found
- suspiciousLinks: string[] — any URLs found that appear suspicious
- explanation: string — detailed reasoning for the verdict

Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

  try {
  const response = await callClaude(
    [{ role: "user", content: `Analyze this email for phishing indicators:\n\n---\n${emailText}\n---` }],
    { system: systemPrompt, maxTokens: 2048 }
  );

    const result = JSON.parse(response) as PhishingResult;
    if (typeof result.score !== "number" || !result.verdict || !Array.isArray(result.redFlags)) {
      throw new Error("Invalid response structure from AI");
    }
    logger.info("PhishingAnalyzer", `Score: ${result.score}, Verdict: ${result.verdict}`);
    return result;
  } catch {
    logger.error("PhishingAnalyzer", "Failed to parse Claude response as JSON");
    return {
      score: 0,
      verdict: "Error",
      redFlags: ["Failed to analyze email. Please try again."],
      suspiciousLinks: [],
      explanation: "An error occurred during analysis.",
    };
  }
}
