import { describe, it, expect } from "vitest";
import { dedupeFindings } from "@/lib/scan-runner";
import type { VulnerabilityResult } from "@/lib/scanners/types";

function f(
  severity: VulnerabilityResult["severity"],
  category: string,
  affectedUrl: string,
  title: string
): VulnerabilityResult {
  return {
    severity,
    category,
    title,
    affectedUrl,
    description: "d",
    remediation: "r",
  };
}

describe("dedupeFindings", () => {
  it("removes exact duplicates (same category + url + title)", () => {
    const a = f("high", "CORS", "https://x.com/", "CORS reflects origin");
    const out = dedupeFindings([a, { ...a }, { ...a }]);
    expect(out).toHaveLength(1);
  });

  it("keeps distinct findings (different url or title)", () => {
    const out = dedupeFindings([
      f("high", "XSS", "https://x.com/?q=1", "Reflected XSS via q"),
      f("high", "XSS", "https://x.com/?search=1", "Reflected XSS via q"), // different url -> kept
      f("high", "XSS", "https://x.com/?q=1", "Reflected XSS via search"), // different title -> kept
    ]);
    expect(out).toHaveLength(3);
  });

  it("keeps the highest severity when duplicates differ only by severity", () => {
    const out = dedupeFindings([
      f("low", "Cookies", "https://x.com/", "Missing Secure"),
      f("high", "Cookies", "https://x.com/", "Missing Secure"),
      f("medium", "Cookies", "https://x.com/", "Missing Secure"),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("high");
  });

  it("does not merge across categories", () => {
    const out = dedupeFindings([
      f("high", "CORS", "https://x.com/", "Misconfiguration"),
      f("high", "Headers", "https://x.com/", "Misconfiguration"),
    ]);
    expect(out).toHaveLength(2);
  });

  it("does not collide on ambiguous concatenation (delimiter safety)", () => {
    // Without a delimiter these two findings share a key ("ABCD") and one
    // would be wrongly dropped. The pipe delimiter keeps them distinct.
    const out = dedupeFindings([
      f("high", "A", "B", "CD"),
      f("low", "AB", "C", "D"),
    ]);
    expect(out).toHaveLength(2);
  });

  it("handles empty input", () => {
    expect(dedupeFindings([])).toEqual([]);
  });
});
