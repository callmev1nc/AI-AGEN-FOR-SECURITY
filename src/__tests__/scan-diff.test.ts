import { describe, it, expect } from "vitest";
import { diffFindings, type FindingLike } from "@/lib/scan-diff";

function f(category: string, affectedUrl: string, title: string, severity = "high"): FindingLike {
  return { severity, category, affectedUrl, title };
}

describe("diffFindings", () => {
  it("marks everything added when there is no baseline", () => {
    const d = diffFindings([], [f("XSS", "u", "t")]);
    expect(d.added).toHaveLength(1);
    expect(d.resolved).toHaveLength(0);
    expect(d.persisted).toHaveLength(0);
  });

  it("marks everything resolved when the current scan is clean", () => {
    const d = diffFindings([f("XSS", "u", "t")], []);
    expect(d.resolved).toHaveLength(1);
    expect(d.added).toHaveLength(0);
  });

  it("marks a finding persisted when present in both scans", () => {
    const d = diffFindings([f("XSS", "u", "t")], [f("XSS", "u", "t")]);
    expect(d.persisted).toHaveLength(1);
    expect(d.added).toHaveLength(0);
    expect(d.resolved).toHaveLength(0);
  });

  it("treats a severity re-rating as the same (persisted) finding", () => {
    const d = diffFindings([f("XSS", "u", "t", "medium")], [f("XSS", "u", "t", "critical")]);
    expect(d.persisted).toHaveLength(1);
    expect(d.added).toHaveLength(0);
    expect(d.resolved).toHaveLength(0);
  });

  it("treats different url or title as different findings", () => {
    const d = diffFindings([f("XSS", "u1", "t")], [f("XSS", "u2", "t")]);
    expect(d.added).toHaveLength(1);
    expect(d.resolved).toHaveLength(1);
  });

  it("handles a mixed scenario (some new, some fixed, some kept)", () => {
    const baseline = [f("XSS", "u", "old"), f("CORS", "u", "c"), f("Headers", "u", "h")];
    const current = [f("CORS", "u", "c"), f("Headers", "u", "h"), f("SQLi", "u", "new")];
    const d = diffFindings(baseline, current);
    expect(d.added.map((x) => x.title)).toEqual(["new"]);
    expect(d.resolved.map((x) => x.title)).toEqual(["old"]);
    expect(d.persisted.map((x) => x.title).sort()).toEqual(["c", "h"]);
  });
});
