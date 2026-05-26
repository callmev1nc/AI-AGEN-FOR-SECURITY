import { logger } from "@/lib/logger";

let anthropicClient: AnthropicClient | null = null;

interface AnthropicMessage {
  role: "user" | "assistant";
  content: string;
}

interface AnthropicResponse {
  content: Array<{ text: string }>;
  usage: { input_tokens: number; output_tokens: number };
}

interface AnthropicClient {
  messages: {
    create: (params: {
      model: string;
      max_tokens: number;
      messages: AnthropicMessage[];
      system?: string;
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
  system?: string;
  retries?: number;
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
      const response = await client.messages.create({
        model,
        max_tokens: maxTokens,
        messages,
        ...(system ? { system } : {}),
      });

      const text = response.content.map((b) => b.text).join("");
      logger.info("AiClient", `Claude response: ${response.usage.input_tokens} in / ${response.usage.output_tokens} out (attempt ${attempt + 1})`);
      return text;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      logger.error("AiClient", `Claude call failed (attempt ${attempt + 1}): ${lastError.message}`);
      if (attempt < retries) {
        const delay = Math.pow(2, attempt) * 1000;
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }

  throw lastError || new Error("Claude call failed");
}

export type { AnthropicMessage, AnthropicResponse, AnthropicClient };
