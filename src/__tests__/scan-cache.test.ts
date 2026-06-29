import { describe, it, expect } from "vitest";
import { initCache } from "@/lib/scanners/scan-context";

describe("scan response cache", () => {
  it("stores and retrieves entries", () => {
    const cache = initCache();
    const entry = {
      statusCode: 200,
      headers: { "content-type": "text/html" },
      body: "<html>ok</html>",
      setCookie: [],
      ts: Date.now(),
    };
    cache.set("http://example.com", entry);
    const got = cache.get("http://example.com");
    expect(got).toBeDefined();
    expect(got!.statusCode).toBe(200);
    expect(got!.body).toBe("<html>ok</html>");
  });

  it("returns undefined for missing keys", () => {
    const cache = initCache();
    expect(cache.get("http://missing.com")).toBeUndefined();
  });

  it("evicts oldest entries when full", () => {
    const cache = initCache();
    // Fill cache beyond max (64)
    for (let i = 0; i < 70; i++) {
      cache.set(`http://example${i}.com`, {
        statusCode: 200,
        headers: {},
        body: `response${i}`,
        setCookie: [],
        ts: Date.now(),
      });
    }
    expect(cache.size()).toBeLessThanOrEqual(64);
  });

  it("deep-copies when constructing response from cache", () => {
    const cache = initCache();
    const entry = {
      statusCode: 200,
      headers: { "x-foo": "bar" },
      body: "hello",
      setCookie: ["session=abc"],
      ts: Date.now(),
    };
    cache.set("http://example.com", entry);
    const got = cache.get("http://example.com")!;
    // Simulate what http.ts does: spread to create a new response object
    const resp = {
      statusCode: got.statusCode,
      headers: { ...got.headers },
      body: got.body,
      setCookie: [...got.setCookie],
    };
    resp.headers["x-foo"] = "mutated";
    resp.setCookie.push("mutated");
    // Cache entry should be unchanged
    const again = cache.get("http://example.com")!;
    expect(again.headers["x-foo"]).toBe("bar");
    expect(again.setCookie).toEqual(["session=abc"]);
  });
});
