"use client";

import { useState } from "react";

interface ToolInputFormProps {
  onSubmit: (input: string) => Promise<void>;
  placeholder?: string;
  buttonLabel?: string;
  loading?: boolean;
  maxLength?: number;
  rows?: number;
  extraFields?: React.ReactNode;
}

export default function ToolInputForm({
  onSubmit,
  placeholder = "Enter your input here...",
  buttonLabel = "Analyze",
  loading = false,
  maxLength = 50000,
  rows = 8,
  extraFields,
}: ToolInputFormProps) {
  const [input, setInput] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim()) return;
    await onSubmit(input.trim());
  }

  return (
    <form onSubmit={handleSubmit} className="card-base space-y-4 p-5">
      <div>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={placeholder}
          maxLength={maxLength}
          rows={rows}
          className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] px-4 py-3 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)] resize-y"
          disabled={loading}
        />
        <p className="mt-1 text-xs text-[var(--text-muted)]">
          {input.length}/{maxLength} characters
        </p>
      </div>
      {extraFields}
      <button
        type="submit"
        disabled={loading || !input.trim()}
        className="rounded-lg bg-[var(--accent)] px-6 py-2.5 text-sm font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? "Processing..." : buttonLabel}
      </button>
    </form>
  );
}
