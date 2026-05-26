import type { VulnerabilityResult } from "@/lib/scanners/types";
import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";

export async function analyzeCodeWithAi(
  code: string,
  fileName: string
): Promise<VulnerabilityResult[]> {
  const systemPrompt = `You are a security code analyzer. Analyze the given code for vulnerabilities.
Return findings as a JSON array of objects with these fields:
- severity: "critical" | "high" | "medium" | "low" | "info"
- category: string (e.g. "SQL Injection", "XSS", "Hardcoded Secret")
- title: string (short description)
- description: string (detailed explanation of the vulnerability)
- evidence: string (the exact code snippet that is vulnerable)
- remediation: string (how to fix the issue)
- lineStart: number (line where vulnerability starts)
- lineEnd: number (line where vulnerability ends)
- suggestedFix: string (the fixed code snippet)

Return ONLY the JSON array. No other text.`;

  const userPrompt = `Analyze this code for security vulnerabilities:

File: ${fileName}

\`\`\`
${code.slice(0, 8000)}
\`\`\``;

  try {
    const response = await callClaude(
      [{ role: "user", content: userPrompt }],
      { system: systemPrompt, maxTokens: 4096 }
    );

    const jsonMatch = response.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      const findings = JSON.parse(jsonMatch[0]) as VulnerabilityResult[];
      return findings.map((f) => ({
        ...f,
        affectedUrl: fileName,
        filePath: fileName,
      }));
    }
  } catch (error) {
    logger.error("CodeAnalyzer", `Failed to analyze ${fileName}: ${error}`);
  }

  return [];
}

export async function analyzeBatchWithAi(
  files: Array<{ path: string; content: string }>
): Promise<VulnerabilityResult[]> {
  const allFindings: VulnerabilityResult[] = [];
  const batchSize = 5;

  for (let i = 0; i < files.length; i += batchSize) {
    const batch = files.slice(i, i + batchSize);
    const batchPromises = batch.map((f) => analyzeCodeWithAi(f.content, f.path));
    const results = await Promise.allSettled(batchPromises);
    for (const result of results) {
      if (result.status === "fulfilled") {
        allFindings.push(...result.value);
      }
    }
  }

  return allFindings;
}
