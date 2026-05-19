import { describe, it, expect } from "vitest";
import { calculateScore, formatDuration } from "../../worker/src/engine";
import type { VulnerabilityResult } from "../../worker/src/scanners/types";

describe("calculateScore", () => {
  it("returns 100 when there are no findings", () => {
    expect(calculateScore([])).toBe(100);
  });

  it("deducts 25 for a critical finding", () => {
    const findings: VulnerabilityResult[] = [
      {
        severity: "critical",
        category: "test",
        title: "test",
        description: "test",
        remediation: "test",
        affectedUrl: "https://example.com",
      },
    ];
    expect(calculateScore(findings)).toBe(75);
  });

  it("deducts 15 for a high finding", () => {
    const findings: VulnerabilityResult[] = [
      {
        severity: "high",
        category: "test",
        title: "test",
        description: "test",
        remediation: "test",
        affectedUrl: "https://example.com",
      },
    ];
    expect(calculateScore(findings)).toBe(85);
  });

  it("deducts 8 for a medium finding", () => {
    const findings: VulnerabilityResult[] = [
      {
        severity: "medium",
        category: "test",
        title: "test",
        description: "test",
        remediation: "test",
        affectedUrl: "https://example.com",
      },
    ];
    expect(calculateScore(findings)).toBe(92);
  });

  it("deducts 3 for a low finding", () => {
    const findings: VulnerabilityResult[] = [
      {
        severity: "low",
        category: "test",
        title: "test",
        description: "test",
        remediation: "test",
        affectedUrl: "https://example.com",
      },
    ];
    expect(calculateScore(findings)).toBe(97);
  });

  it("does not deduct for info findings", () => {
    const findings: VulnerabilityResult[] = [
      {
        severity: "info",
        category: "test",
        title: "test",
        description: "test",
        remediation: "test",
        affectedUrl: "https://example.com",
      },
    ];
    expect(calculateScore(findings)).toBe(100);
  });

  it("accumulates deductions from multiple findings", () => {
    const findings: VulnerabilityResult[] = [
      { severity: "critical", category: "a", title: "a", description: "a", remediation: "a", affectedUrl: "https://example.com" },
      { severity: "high", category: "b", title: "b", description: "b", remediation: "b", affectedUrl: "https://example.com" },
      { severity: "medium", category: "c", title: "c", description: "c", remediation: "c", affectedUrl: "https://example.com" },
    ];
    expect(calculateScore(findings)).toBe(100 - 25 - 15 - 8);
  });

  it("clamps the score to a minimum of 0", () => {
    const findings: VulnerabilityResult[] = Array.from({ length: 10 }, () => ({
      severity: "critical" as const,
      category: "x",
      title: "x",
      description: "x",
      remediation: "x",
      affectedUrl: "https://example.com",
    }));
    expect(calculateScore(findings)).toBe(0);
  });

  it("clamps the score to a maximum of 100", () => {
    const findings: VulnerabilityResult[] = [
      {
        severity: "info",
        category: "x",
        title: "x",
        description: "x",
        remediation: "x",
        affectedUrl: "https://example.com",
      },
      {
        severity: "low" as const,
        category: "x",
        title: "x",
        description: "x",
        remediation: "x",
        affectedUrl: "https://example.com",
      },
    ];
    expect(calculateScore(findings)).toBe(97);
  });
});

describe("formatDuration", () => {
  it("formats seconds", () => {
    expect(formatDuration(5000)).toBe("5s");
  });

  it("formats minutes and seconds", () => {
    expect(formatDuration(125000)).toBe("2m 5s");
  });

  it("formats exactly 1 minute", () => {
    expect(formatDuration(60000)).toBe("1m 0s");
  });

  it("handles zero", () => {
    expect(formatDuration(0)).toBe("0s");
  });
});
