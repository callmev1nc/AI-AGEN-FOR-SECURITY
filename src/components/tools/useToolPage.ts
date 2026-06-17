"use client";

import { useState } from "react";

/**
 * Shared state machine for the single-input tool pages (phishing, secrets,
 * cve, headers, password). Replaces the result/loading/error trio + the
 * identical try/catch around the tRPC mutation that every tool page duplicated.
 *
 * `run` receives the (already-trimmed) input string and returns the result.
 * Throw inside `run` to surface an error — used by tools that validate input
 * first (CVE format, URL format).
 */
export function useToolPage<TResult>(run: (input: string) => Promise<TResult>) {
  const [result, setResult] = useState<TResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit(input: string) {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      setResult(await run(input));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }

  return { result, loading, error, submit };
}
