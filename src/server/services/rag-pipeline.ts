import { createAdminClient } from "@/lib/supabase/admin";
import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";

interface Message {
  role: "user" | "assistant";
  content: string;
}

export async function answerSecurityQuestion(
  question: string,
  scanId: string,
  userId: string
): Promise<{ answer: string; sources: string[] }> {
  const admin = createAdminClient();

  const { data: scan, error } = await admin
    .from("scans")
    .select("*, vulnerabilities(*)")
    .eq("id", scanId)
    .eq("userId", userId)
    .single();

  if (error || !scan) throw new Error("Scan not found");
  if (scan.status !== "completed") throw new Error("Scan not completed yet");

  const { data: history } = await admin
    .from("chat_messages")
    .select("role, content")
    .eq("scan_id", scanId)
    .eq("user_id", userId)
    .order("created_at", { ascending: true })
    .limit(20);

  const messages: Message[] = (history || []).map((m: { role: string; content: string }) => ({
    role: m.role as "user" | "assistant",
    content: m.content,
  }));

  const vulnsText = scan.vulnerabilities.map((v: { severity: string; title: string; description: string; category: string; remediation: string }, i: number) =>
    `[${i + 1}] ${v.severity.toUpperCase()}: ${v.title}
   Category: ${v.category}
   Description: ${v.description}
   Remediation: ${v.remediation}`
  ).join("\n\n");

  const systemPrompt = `You are a security analysis assistant. You help users understand scan results and answer security questions.

Context - Scan Results for ${scan.targetUrl}:
- Scan Type: ${scan.scanType}
- Scan Level: ${scan.scanLevel}
- Overall Score: ${scan.overallScore ?? 0}/100
- Total Findings: ${scan.vulnerabilities.length}

Vulnerability Findings:
${vulnsText || "No vulnerabilities found in this scan."}

Guidelines:
1. Answer questions using ONLY the scan results above
2. If the question is not related to the scan, politely redirect
3. Reference specific vulnerability IDs when relevant
4. Provide practical remediation advice
5. Be concise but thorough
6. If you reference a finding, include its number in brackets like [1]`;

  messages.push({ role: "user", content: question });

  const answer = await callClaude(messages, {
    system: systemPrompt,
    maxTokens: 2048,
  });

  const sourceIds: string[] = [];
  const sourceMatch = answer.match(/\[(\d+)\]/g);
  if (sourceMatch) {
    sourceMatch.forEach((m) => {
      const id = m.replace(/[\[\]]/g, "");
      if (!sourceIds.includes(id)) sourceIds.push(id);
    });
  }

  const { error: insertError } = await admin.from("chat_messages").insert([
    { scan_id: scanId, user_id: userId, role: "user", content: question },
    { scan_id: scanId, user_id: userId, role: "assistant", content: answer, sources: sourceIds },
  ]);

  if (insertError) {
    logger.error("RagPipeline", `Failed to save chat messages: ${insertError.message}`);
  }

  return { answer, sources: sourceIds };
}
