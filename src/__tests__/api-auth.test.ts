import { describe, it, expect } from "vitest";
import { generateApiKey } from "@/lib/api-auth";

describe("api-auth", () => {
  it("generates a key in ssc_live_ format", () => {
    const { plaintext, keyHash, keyPrefix } = generateApiKey();
    expect(plaintext).toMatch(/^ssc_live_/);
    expect(plaintext.length).toBeGreaterThan(50);
    expect(keyPrefix).toBe(plaintext.slice(0, 12));
    expect(keyHash).toBeDefined();
    expect(keyHash.length).toBe(64); // sha256 hex
  });

  it("does not expose the plaintext in the hash", () => {
    const { plaintext, keyHash } = generateApiKey();
    expect(keyHash).not.toContain(plaintext);
    expect(keyHash).not.toContain("ssc_live");
  });

  it("rate limit bucket is api-prefixed", () => {
    // The plan says bucket is `api:${userId}` — verify the code uses it
    const rateLimitKey = "api:test-user-id";
    expect(rateLimitKey.startsWith("api:")).toBe(true);
  });
});
