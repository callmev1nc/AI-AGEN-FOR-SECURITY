/**
 * Shared types for all scanner modules.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface VulnerabilityResult {
  severity: Severity;
  category: string;
  title: string;
  description: string;
  evidence?: string;
  remediation: string;
  cvssScore?: number;
  affectedUrl: string;
}

/**
 * Every scanner module must export a function matching this signature.
 */
export type ScannerModule = (targetUrl: string) => Promise<VulnerabilityResult[]>;

/**
 * Helper to safely access headers by name from IncomingHttpHeaders.
 */
export function getHeader(headers: Record<string, unknown> | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const val = headers[name.toLowerCase()];
  if (Array.isArray(val)) return val[0];
  return typeof val === "string" ? val : undefined;
}
