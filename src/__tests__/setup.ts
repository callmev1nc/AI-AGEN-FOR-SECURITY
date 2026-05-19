import "@testing-library/jest-dom/vitest";

import { vi } from "vitest";

globalThis.fetch = vi.fn().mockResolvedValue({ ok: true } as Response);
