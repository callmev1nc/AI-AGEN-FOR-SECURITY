# SecureScan — AI-Powered Security Scanning Platform

## Tech Stack
- Next.js 16 (App Router) + TypeScript 5
- Supabase (PostgreSQL + Auth + Storage)
- tRPC for type-safe APIs
- Tailwind CSS 4
- Anthropic API (via raw fetch in `src/lib/ai/client.ts`) for AI features

## Project Structure
- `src/lib/scanners/` — Scanner modules, each exports `scan(targetUrl) => VulnerabilityResult[]`
- `src/lib/ai/` — Claude API client, AI services (report writer, code analyzer, RAG)
- `src/lib/scan-runner.ts` — Orchestrates scanners by scanType + level
- `src/server/routers/` — tRPC routers (auth, scan, chat)
- `src/app/dashboard/` — Protected dashboard pages
- `src/components/report/` — PDF report templates

## Conventions
- Scanner modules follow `(targetUrl: string) => Promise<VulnerabilityResult[]>` signature
- Each scanner has `scanType` ("website" | "api" | "infrastructure") and `level` ("quick" | "standard" | "deep")
- All AI calls go through `src/lib/ai/client.ts` — never call Claude SDK directly
- Database changes via SQL migration files (not Prisma migrations)
- Severity levels: critical, high, medium, low, info
- Use pnpm, not npm or yarn

## Environment Variables
See `.env.example`. Key ones:
- `NEXT_PUBLIC_SUPABASE_URL` / `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `ANTHROPIC_API_KEY`
- `STRIPE_SECRET_KEY` (billing phase)

## Testing
- `pnpm test` runs Vitest
- Scanners tested with mocked HTTP responses
- AI features tested with mocked Claude responses
