import { describe, it, expect, beforeEach } from "vitest";
import { vi } from "vitest";

// Hoisted mock so the factory can reference it. We control DNS so the SSRF
// guard never touches the real network. Provide both a `default` and named
// export — vitest's builtin-module interop accesses `.default`.
const { lookupMock } = vi.hoisted(() => ({ lookupMock: vi.fn() }));
vi.mock("node:dns/promises", () => {
  const lookup = (...args: unknown[]) => lookupMock(...(args as never[]));
  return { default: { lookup }, lookup };
});

import {
  isPrivateIp,
  resolveAndAssertPublic,
  safeFetch,
} from "@/lib/safe-fetch";
import { scannerRequest } from "@/lib/scanners/http";

describe("isPrivateIp — the SSRF allow/deny decision", () => {
  const blocked = [
    "127.0.0.1",
    "10.0.0.5",
    "192.168.1.1",
    "172.16.0.1",
    "172.31.255.255",
    "169.254.169.254", // cloud metadata
    "0.0.0.0",
    "100.64.0.1", // CGNAT
    "::1", // IPv6 loopback
    "fc00::1", // IPv6 ULA
    "fe80::1", // IPv6 link-local
    "::ffff:127.0.0.1", // v4-mapped loopback
  ];
  for (const ip of blocked) {
    it(`blocks ${ip}`, () => {
      expect(isPrivateIp(ip)).toBe(true);
    });
  }

  const allowed = [
    "8.8.8.8",
    "1.1.1.1",
    "203.0.113.10",
    "2606:4700:4700::1111",
    "::ffff:8.8.8.8", // v4-mapped public
  ];
  for (const ip of allowed) {
    it(`allows ${ip}`, () => {
      expect(isPrivateIp(ip)).toBe(false);
    });
  }

  it("treats non-IP literals as not-private (hostname path is separate)", () => {
    expect(isPrivateIp("example.com")).toBe(false);
  });
});

describe("resolveAndAssertPublic", () => {
  beforeEach(() => lookupMock.mockReset());

  it("accepts a public IP literal without DNS", async () => {
    await expect(resolveAndAssertPublic("8.8.8.8")).resolves.toEqual(["8.8.8.8"]);
  });

  it("rejects the cloud-metadata IP literal", async () => {
    await expect(resolveAndAssertPublic("169.254.169.254")).rejects.toMatchObject({
      code: "BLOCKED_PRIVATE_IP",
    });
  });

  it("rejects IPv6 loopback", async () => {
    await expect(resolveAndAssertPublic("::1")).rejects.toMatchObject({
      code: "BLOCKED_PRIVATE_IP",
    });
  });

  it("rejects local/internal hostnames", async () => {
    await expect(resolveAndAssertPublic("localhost")).rejects.toMatchObject({
      code: "BLOCKED_HOSTNAME",
    });
    await expect(resolveAndAssertPublic("db.internal")).rejects.toMatchObject({
      code: "BLOCKED_HOSTNAME",
    });
  });

  it("accepts a hostname that resolves to a public IP", async () => {
    lookupMock.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    await expect(resolveAndAssertPublic("example.com")).resolves.toEqual([
      "93.184.216.34",
    ]);
  });

  it("blocks DNS-rebinding: a hostname resolving to a private IP is rejected", async () => {
    lookupMock.mockResolvedValue([{ address: "10.1.2.3", family: 4 }]);
    await expect(resolveAndAssertPublic("rebinder.attacker")).rejects.toMatchObject({
      code: "BLOCKED_PRIVATE_IP",
    });
  });

  it("rejects if ANY resolved address is private", async () => {
    lookupMock.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "169.254.169.254", family: 4 },
    ]);
    await expect(resolveAndAssertPublic("mixed.example")).rejects.toMatchObject({
      code: "BLOCKED_PRIVATE_IP",
    });
  });
});

describe("safeFetch protocol guard", () => {
  it("blocks non-http(s) protocols before any network call", async () => {
    await expect(safeFetch("file:///etc/passwd")).rejects.toMatchObject({
      code: "BLOCKED_PROTOCOL",
    });
    await expect(safeFetch("ftp://example.com/x")).rejects.toMatchObject({
      code: "BLOCKED_PROTOCOL",
    });
  });
});

describe("scannerRequest — graceful null on SSRF block", () => {
  it("resolves null when the target is a private IP (no throw)", async () => {
    await expect(
      scannerRequest("http://169.254.169.254/latest/meta-data/")
    ).resolves.toBeNull();
    await expect(scannerRequest("http://127.0.0.1/")).resolves.toBeNull();
    await expect(scannerRequest("http://10.0.0.1/")).resolves.toBeNull();
  });

  it("re-throws the SafeFetchError when throwOnBlock is set", async () => {
    await expect(
      scannerRequest("http://169.254.169.254/", { throwOnBlock: true })
    ).rejects.toMatchObject({ code: "BLOCKED_PRIVATE_IP" });
  });
});
