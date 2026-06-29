import { logger } from "@/lib/logger";

let anthropicClient: AnthropicClient | null = null;

interface AnthropicMessage {
  role: "user" | "assistant";
  content: string;
}

interface AnthropicResponse {
  content: Array<{ text: string }>;
  usage: { input_tokens: number; output_tokens: number; cache_read_input_tokens?: number; cache_creation_input_tokens?: number };
}

export interface CachedSystemPrompt {
  text: string;
  cache: true;
}

type SystemParam = string | CachedSystemPrompt;

interface AnthropicClient {
  messages: {
    create: (params: {
      model: string;
      max_tokens: number;
      messages: AnthropicMessage[];
      system?: string | Array<{ type: "text"; text: string; cache_control?: { type: "ephemeral" } }>;
    }) => Promise<AnthropicResponse>;
  };
}

function getClient(): AnthropicClient {
  if (anthropicClient) return anthropicClient;

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY is not set");
  }

  anthropicClient = {
    messages: {
      create: async (params) => {
        const response = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": apiKey,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify(params),
        });

        if (!response.ok) {
          const error = await response.text();
          throw new Error(`Anthropic API error (${response.status}): ${error}`);
        }

        return response.json();
      },
    },
  };

  return anthropicClient;
}

export interface AiCallOptions {
  model?: string;
  maxTokens?: number;
  system?: SystemParam;
  retries?: number;
}

/**
 * Only retry errors that can plausibly succeed on a subsequent attempt:
 *  - HTTP 429 (rate limit) and any 5xx (incl. 529 "overloaded") from Anthropic.
 *  - Non-HTTP failures (network / connection errors) — no status in the message.
 * 4xx auth / validation / payload errors (400/401/403/413/…) are deterministic
 * failures, so retrying them only wastes time and tokens.
 */
function isRetryableAiError(error: Error): boolean {
  const match = error.message.match(/Anthropic API error \((\d+)\)/);
  if (match) {
    const status = Number(match[1]);
    return status === 429 || (status >= 500 && status <= 599);
  }
  return true; // network / connection error
}

export async function callClaude(
  messages: AnthropicMessage[],
  options: AiCallOptions = {}
): Promise<string> {
  const {
    model = "claude-sonnet-4-20250514",
    maxTokens = 4096,
    system,
    retries = 2,
  } = options;

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const client = getClient();
      const systemParam = typeof system === "object" && system !== null && "cache" in system && system.cache
        ? [{ type: "text" as const, text: system.text, cache_control: { type: "ephemeral" as const } }]
        : typeof system === "string"
          ? system
          : undefined;
      const response = await client.messages.create({
        model,
        max_tokens: maxTokens,
        messages,
        ...(systemParam !== undefined ? { system: systemParam } : {}),
      });

      const text = response.content.map((b) => b.text).join("");
      const cacheRead = response.usage.cache_read_input_tokens ?? 0;
      const cacheCreate = response.usage.cache_creation_input_tokens ?? 0;
      const cacheInfo = cacheRead || cacheCreate ? ` (cache read:${cacheRead} create:${cacheCreate})` : "";
      logger.info("AiClient", `Claude response: ${response.usage.input_tokens} in / ${response.usage.output_tokens} out${cacheInfo} (attempt ${attempt + 1})`);
      return text;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      logger.error("AiClient", `Claude call failed (attempt ${attempt + 1}): ${lastError.message}`);
      if (attempt < retries && isRetryableAiError(lastError)) {
        const delay = Math.pow(2, attempt) * 1000;
        await new Promise((r) => setTimeout(r, delay));
      } else {
        break; // non-retryable error (e.g. 400/401/403) or retries exhausted
      }
    }
  }

  throw lastError || new Error("Claude call failed");
}

export type { AnthropicMessage, AnthropicResponse, AnthropicClient };
