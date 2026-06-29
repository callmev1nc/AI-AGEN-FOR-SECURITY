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
  suggestedFix?: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
}

export interface FileInput {
  path: string;
  content: string;
}

export interface FileScanResult {
  filePath: string;
  findings: VulnerabilityResult[];
}
