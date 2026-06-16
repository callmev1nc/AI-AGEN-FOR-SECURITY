import "@testing-library/jest-dom/vitest";

// NOTE: we intentionally do NOT install a blanket global fetch mock here.
// Scanner tests use `nock` to intercept Node http/https requests at the module
// level, and AI client tests mock `@/lib/ai/client` directly. A blanket
// `globalThis.fetch = vi.fn()` here would mask real (unmocked) network calls
// and produce false greens. Mock fetch per-test where needed.
