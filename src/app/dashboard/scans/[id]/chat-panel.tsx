"use client";

import { useState, useEffect, useRef } from "react";
import { trpcClient } from "@/lib/trpc-client";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  sources: string[] | null;
}

interface Props {
  scanId: string;
}

export default function ChatPanel({ scanId }: Props) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    trpcClient.chat.getHistory.query({ scanId })
      .then((data) => setMessages(data as ChatMessage[]))
      .catch(() => setMessages([]));
  }, [scanId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput("");
    setLoading(true);
    setError("");

    setMessages((prev) => [...prev, { id: "temp", role: "user" as const, content: userMessage, sources: null }]);

    try {
      const result = await trpcClient.chat.sendMessage.mutate({
        scanId,
        message: userMessage,
      });
      const msgId = Date.now().toString();
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== "temp"),
        { id: `user-${msgId}`, role: "user", content: userMessage, sources: null },
        { id: `asst-${msgId}`, role: "assistant", content: result.answer, sources: result.sources },
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to send message");
      setMessages((prev) => prev.filter((m) => m.id !== "temp"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="border-t border-[var(--border)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between p-4 text-sm text-[var(--text-secondary)] hover:text-white transition-colors"
      >
        <span className="font-medium">Security Chat</span>
        <svg
          className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`}
          viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
        >
          <path d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="border-t border-[var(--border)]">
          <div className="h-64 space-y-3 overflow-y-auto p-4">
            {messages.map((msg) => (
              <div key={msg.id} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div
                  className={`max-w-[80%] rounded-xl px-4 py-2.5 text-sm ${
                    msg.role === "user"
                      ? "bg-[var(--accent)] text-black"
                      : "bg-[var(--bg-card)] text-[var(--text-secondary)] border border-[var(--border)]"
                  }`}
                >
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                  {msg.sources && msg.sources.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {msg.sources.map((s, i) => (
                        <span key={i} className="rounded bg-[var(--accent-dim)] px-1.5 py-0.5 text-[10px] text-[var(--accent)]">
                          #{s}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {error && (
              <div className="rounded-lg bg-[var(--critical-dim)] p-3 text-xs text-[var(--critical)]">{error}</div>
            )}
            {loading && (
              <div className="flex justify-start">
                <div className="rounded-xl bg-[var(--bg-card)] border border-[var(--border)] px-4 py-2.5">
                  <div className="flex gap-1">
                    <div className="h-2 w-2 animate-bounce rounded-full bg-[var(--text-muted)]" style={{ animationDelay: "0ms" }} />
                    <div className="h-2 w-2 animate-bounce rounded-full bg-[var(--text-muted)]" style={{ animationDelay: "150ms" }} />
                    <div className="h-2 w-2 animate-bounce rounded-full bg-[var(--text-muted)]" style={{ animationDelay: "300ms" }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <form onSubmit={handleSend} className="flex items-center gap-2 border-t border-[var(--border)] p-3">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about a vulnerability..."
              disabled={loading}
              className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-3 py-2 text-sm text-white placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent)]"
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50"
            >
              Send
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
