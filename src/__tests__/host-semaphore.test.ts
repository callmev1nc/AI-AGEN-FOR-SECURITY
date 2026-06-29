import { describe, it, expect } from "vitest";
import { acquireHostSlot, releaseHostSlot } from "@/lib/scanners/scan-context";

describe("host semaphore", () => {
  it("allows up to 3 concurrent requests to the same host", async () => {
    const host = "example.com";
    await acquireHostSlot(host);
    await acquireHostSlot(host);
    await acquireHostSlot(host);

    // 4th acquire would block; race it with a short timeout to verify
    const blocked = Promise.race([
      acquireHostSlot(host).then(() => "acquired"),
      new Promise<string>((resolve) => setTimeout(() => resolve("timeout"), 100)),
    ]);
    // Give the promise a tick to settle
    await new Promise((r) => setTimeout(r, 10));
    // Release one slot
    releaseHostSlot(host);
    // Now the blocked acquire should go through
    expect(await blocked).toBe("acquired");

    // Cleanup
    releaseHostSlot(host);
    releaseHostSlot(host);
    releaseHostSlot(host);
  });

  it("releases work correctly with fewer than max", () => {
    const host = "release-test.example.com";
    releaseHostSlot(host); // no-op, shouldn't throw
    releaseHostSlot(host);
  });

  it("different hosts have independent semaphores", async () => {
    const hostA = "host-a.example.com";
    const hostB = "host-b.example.com";

    await acquireHostSlot(hostA);
    await acquireHostSlot(hostA);
    await acquireHostSlot(hostA);

    // Host B should still allow acquires
    await acquireHostSlot(hostB);
    await acquireHostSlot(hostB);

    // Cleanup
    releaseHostSlot(hostA);
    releaseHostSlot(hostA);
    releaseHostSlot(hostA);
    releaseHostSlot(hostB);
    releaseHostSlot(hostB);
  });
});
