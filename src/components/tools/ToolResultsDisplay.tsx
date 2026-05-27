"use client";

import { useState } from "react";

interface ToolResultsDisplayProps {
  children: React.ReactNode;
  title?: string;
}

export default function ToolResultsDisplay({ children, title = "Results" }: ToolResultsDisplayProps) {
  return (
    <div className="card-base p-5">
      <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
        {title}
      </h2>
      {children}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button
      onClick={handleCopy}
      className="rounded bg-[var(--bg-card-hover)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-all hover:brightness-110"
    >
      {copied ? "Copied!" : label}
    </button>
  );
}

export function CodeBlock({ code, language = "" }: { code: string; language?: string }) {
  return (
    <div className="relative mt-2 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] overflow-hidden">
      {language && (
        <div className="border-b border-[var(--border)] px-4 py-1.5 text-xs text-[var(--text-muted)]" style={{ fontFamily: "var(--font-jetbrains)" }}>
          {language}
        </div>
      )}
      <div className="flex items-start justify-between gap-2 p-4">
        <pre className="overflow-x-auto text-sm leading-relaxed" style={{ fontFamily: "var(--font-jetbrains)" }}>
          <code>{code}</code>
        </pre>
        <CopyButton text={code} />
      </div>
    </div>
  );
}

export function ScoreGauge({ score, label, higherIsWorse = true }: { score: number; label: string; higherIsWorse?: boolean }) {
  const clamped = Math.min(100, Math.max(0, Math.round(score)));

  const color = higherIsWorse
    ? clamped >= 80 ? "var(--critical)" : clamped >= 60 ? "var(--medium)" : clamped >= 40 ? "var(--warning)" : "var(--accent)"
    : clamped >= 80 ? "var(--accent)" : clamped >= 60 ? "var(--warning)" : clamped >= 40 ? "var(--medium)" : "var(--critical)";

  return (
    <div className="flex items-center gap-4">
      <div className="relative h-20 w-20">
        <svg className="h-20 w-20 -rotate-90" viewBox="0 0 72 72">
          <circle cx="36" cy="36" r="30" fill="none" stroke="var(--border)" strokeWidth="6" />
          <circle
            cx="36" cy="36" r="30"
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeDasharray={`${(clamped / 100) * 188.5} 188.5`}
            strokeLinecap="round"
          />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-lg font-bold" style={{ fontFamily: "var(--font-jetbrains)" }}>
          {clamped}
        </span>
      </div>
      <div>
        <p className="text-sm font-medium">{label}</p>
      </div>
    </div>
  );
}
