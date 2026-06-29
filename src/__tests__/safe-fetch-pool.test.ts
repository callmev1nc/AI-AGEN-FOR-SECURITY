import { describe, it, expect, afterEach } from "vitest";
import { getPoolAgent, drainPool, poolSize } from "@/lib/safe-fetch-pool";

describe("safe-fetch-pool", () => {
  afterEach(() => {
    drainPool();
  });

  it("returns an agent for a given protocol/host/port/ip", () => {
    const agent = getPoolAgent("https:", "example.com", 443, "93.184.216.34");
    expect(agent).toBeDefined();
    expect(agent.maxSockets).toBe(6);
  });

  it("returns the same agent for the same key", () => {
    const a = getPoolAgent("https:", "example.com", 443, "93.184.216.34");
    const b = getPoolAgent("https:", "example.com", 443, "93.184.216.34");
    expect(a).toBe(b);
  });

  it("returns different agents for different IPs", () => {
    const a = getPoolAgent("https:", "example.com", 443, "93.184.216.34");
    const b = getPoolAgent("https:", "example.com", 443, "1.2.3.4");
    expect(a).not.toBe(b);
  });

  it("returns different agents for different ports", () => {
    const a = getPoolAgent("https:", "example.com", 443, "93.184.216.34");
    const b = getPoolAgent("https:", "example.com", 8080, "93.184.216.34");
    expect(a).not.toBe(b);
  });

  it("poolSize returns the number of unique agents", () => {
    getPoolAgent("https:", "example.com", 443, "93.184.216.34");
    getPoolAgent("https:", "google.com", 443, "142.250.80.14");
    getPoolAgent("http:", "example.com", 80, "93.184.216.34");
    expect(poolSize()).toBe(3);
  });

  it("drainPool clears all agents", () => {
    getPoolAgent("https:", "example.com", 443, "93.184.216.34");
    drainPool();
    expect(poolSize()).toBe(0);
  });
});
