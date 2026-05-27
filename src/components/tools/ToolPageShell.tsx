"use client";

import Link from "next/link";

interface ToolPageShellProps {
  title: string;
  description: string;
  children: React.ReactNode;
}

export default function ToolPageShell({ title, description, children }: ToolPageShellProps) {
  return (
    <div className="animate-fade-in-up space-y-6">
      <div>
        <nav className="mb-4 text-sm text-[var(--text-muted)]">
          <Link href="/dashboard/tools" className="hover:text-[var(--accent)] transition-colors">
            Security Tools
          </Link>
          <span className="mx-2">/</span>
          <span className="text-[var(--text-secondary)]">{title}</span>
        </nav>
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          {title}
        </h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">{description}</p>
      </div>
      {children}
    </div>
  );
}
