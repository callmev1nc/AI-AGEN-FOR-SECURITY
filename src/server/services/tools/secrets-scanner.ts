import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";
import { SECRET_PATTERNS } from "@/lib/scanners/infra-secrets";

interface SecretsFinding {
  lineNumber: number;
  match: string;
  patternName: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  context: string;
  isFalsePositive: boolean;
  confidence: number;
}

interface SecretsResult {
  findings: SecretsFinding[];
  summary: string;
}

function getContextLines(lines: string[], lineIndex: number): string {
  const start = Math.max(0, lineIndex - 2);
  const end = Math.min(lines.length, lineIndex + 3);
  return lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join("\n");
}

function regexScan(content: string): SecretsFinding[] {
  const lines = content.split("\n");
  const findings: SecretsFinding[] = [];

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    const matches = content.matchAll(pattern.regex);
    for (const match of matches) {
      const matchIndex = match.index ?? 0;
      const lineIndex = content.substring(0, matchIndex).split("\n").length - 1;
      const masked = match[0].length > 8
        ? match[0].slice(0, 4) + "..." + match[0].slice(-4)
        : match[0];

      findings.push({
        lineNumber: lineIndex + 1,
        match: masked,
        patternName: pattern.name,
        severity: pattern.severity,
        context: getContextLines(lines, lineIndex),
        isFalsePositive: false,
        confidence: 80,
      });
    }
  }

  return findings;
}

export async function scanSecrets(content: string): Promise<SecretsResult> {
  const regexFindings = regexScan(content);

  if (regexFindings.length === 0) {
    return { findings: [], summary: "No secrets or credentials detected in the provided content." };
  }

  const findingsJson = regexFindings.map((f) => ({
    line: f.lineNumber,
    pattern: f.patternName,
    match: f.match,
  }));

  const systemPrompt = `You are a security expert triaging potential secrets in code. For each finding, determine if it's a genuine secret or a false positive (e.g., example values, test data, documentation). Return a JSON object with:
- summary: string (brief summary of findings)
- falsePositives: number[] (array of line numbers that are false positives)
- confidenceAdjustments: Record<number, number> (line number -> adjusted confidence 0-100)

Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

  try {
  const response = await callClaude(
    [{ role: "user", content: `Triage these potential secrets for false positives:\n\n${JSON.stringify(findingsJson, null, 2)}` }],
    { system: systemPrompt, maxTokens: 2048 }
  );

    const aiResult = JSON.parse(response) as {
      summary: string;
      falsePositives: number[];
      confidenceAdjustments: Record<string, number>;
    };
    if (!Array.isArray(aiResult.falsePositives)) {
      throw new Error("Invalid response structure from AI");
    }

    const adjustedFindings = regexFindings.map((f) => {
      const isFP = aiResult.falsePositives.includes(f.lineNumber);
      const adjustedConfidence = aiResult.confidenceAdjustments?.[String(f.lineNumber)];
      return {
        ...f,
        isFalsePositive: isFP,
        confidence: adjustedConfidence ?? (isFP ? 20 : f.confidence),
      };
    });

    return { findings: adjustedFindings, summary: aiResult.summary };
  } catch {
    logger.error("SecretsScanner", "Failed to parse AI triage response");
    return { findings: regexFindings, summary: "Regex scan completed. AI triage unavailable." };
  }
}
