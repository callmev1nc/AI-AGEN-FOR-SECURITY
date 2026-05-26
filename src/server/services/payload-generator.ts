import { callClaude } from "@/lib/ai/client";

const cache = new Map<string, { payloads: string[]; expiresAt: number }>();

const CATEGORY_PROMPTS: Record<string, string> = {
  "sql-injection": `Generate 5 SQL injection payloads for fuzzing an API. Include:
1. Classic SQLi (error-based)
2. UNION-based injection
3. Blind SQLi (time-based)
4. Boolean-based blind
5. NoSQL injection (MongoDB)

Return only the payloads as a JSON array of strings. No explanation.`,

  "path-traversal": `Generate 5 path traversal payloads for fuzzing an API. Include:
1. Simple ../ traversal
2. Double-encoded traversal
3. Unicode-encoded traversal
4. Null byte injection
5. Absolute path bypass

Return only the payloads as a JSON array of strings. No explanation.`,

  "auth-bypass": `Generate 5 auth bypass payloads for fuzzing an API. Include:
1. Missing auth header
2. Empty JWT token
3. JWT with alg: none
4. SQL injection in login field
5. Role escalation attempt

Return only the payloads as a JSON array of strings. No explanation.`,
};

export async function generateFuzzPayloads(targetUrl: string, category: string): Promise<string[]> {
  const cacheKey = `${targetUrl}:${category}`;
  const cached = cache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.payloads;
  }

  const prompt = CATEGORY_PROMPTS[category];
  if (!prompt) return [];

  const response = await callClaude(
    [{ role: "user", content: prompt }],
    { maxTokens: 1024 }
  );

  try {
    const jsonMatch = response.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      const payloads = JSON.parse(jsonMatch[0]) as string[];
      cache.set(cacheKey, { payloads, expiresAt: Date.now() + 3600000 });
      return payloads;
    }
  } catch {
    // fall through
  }

  return [];
}
