import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { createTRPCRouter, protectedProcedure, internalError } from "@/lib/trpc";
import { checkRateLimit } from "@/lib/rate-limit";
import { resolveAndAssertPublic } from "@/lib/safe-fetch";
import { diffFindings, type FindingLike } from "@/lib/scan-diff";
import { generatePdfReport } from "@/server/services/report";
import { generateAiReport } from "@/server/services/ai-report-writer";

/** Severity display order (critical first). Postgres text-enum ordering is
 *  alphabetical, which puts "info" before "low" before "medium", so we sort
 *  client-side after fetching. */
const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
function bySeverityRank(a: { severity: string }, b: { severity: string }): number {
  return (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99);
}

export const scanRouter = createTRPCRouter({
  listReports: protectedProcedure.query(async ({ ctx }) => {
    const { data, error } = await ctx.admin
      .from("reports")
      .select("id, scanId, format, storagePath, createdAt, scans(targetUrl, overallScore)")
      .eq("userId", ctx.user.id)
      .order("createdAt", { ascending: false })
      .limit(50);

    if (error) {
      throw internalError("ScanRouter", error);
    }
    return data;
  }),

  getReportDownloadUrl: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .query(async ({ ctx, input }) => {
      const { data: report, error } = await ctx.admin
        .from("reports")
        .select("storagePath, userId")
        .eq("id", input.reportId)
        .eq("userId", ctx.user.id)
        .single();

      if (error || !report) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Report not found" });
      }

      const { data: signedUrl, error: signedUrlError } = await ctx.admin.storage
        .from("reports")
        .createSignedUrl(report.storagePath, 60 * 60);

      if (signedUrlError || !signedUrl) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to generate download URL",
        });
      }
      return { downloadUrl: signedUrl.signedUrl };
    }),

  exportPdf: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const { report } = await generatePdfReport(input.id, ctx.user.id);
      const { data: signedUrl, error: signedUrlError } = await ctx.admin.storage
        .from("reports")
        .createSignedUrl(report.storagePath, 60 * 60);
      if (signedUrlError || !signedUrl) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to generate download URL" });
      }
      return { downloadUrl: signedUrl.signedUrl, report };
    }),
  generateAiReport: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const result = await generateAiReport(input.id, ctx.user.id);
      return result;
    }),
  create: protectedProcedure
    .input(
      z.object({
        targetUrl: z.string().url("Invalid URL").refine((url) => {
          try {
            const parsed = new URL(url);
            // Sync sanity check only — the real SSRF/target check (private IPs,
            // cloud metadata, IPv6, DNS-rebinding) is the async
            // resolveAndAssertPublic call in the handler below.
            return parsed.protocol === "http:" || parsed.protocol === "https:";
          } catch {
            return false;
          }
        }, "Target must be a valid http(s) URL"),
        scanLevel: z.enum(["quick", "standard", "deep"]).default("standard"),
        scanType: z.enum(["website", "api", "infrastructure"]).default("website"),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const { data: userProfile } = await ctx.admin
        .from("users")
        .select("plan")
        .eq("id", ctx.user.id)
        .single();

      const userPlan = (userProfile?.plan as string) || "free";

      const rateLimit = await checkRateLimit(`scan:${ctx.user.id}`, userPlan);
      if (!rateLimit.success) {
        throw new TRPCError({
          code: "TOO_MANY_REQUESTS",
          message: `Rate limit exceeded. Your ${userPlan} plan allows ${rateLimit.limit} scans per hour. Upgrade at /pricing.`,
        });
      }

      // SSRF defense-in-depth: confirm the target resolves to a public address
      // before we create/queue anything. Blocks cloud metadata (169.254.169.254),
      // RFC1918, loopback, link-local, and DNS-rebinding. safeFetch re-checks
      // at scan time; this gives a fast, friendly error at creation.
      try {
        await resolveAndAssertPublic(new URL(input.targetUrl).hostname);
      } catch {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Scanning private, local, or internal addresses is not allowed.",
        });
      }

      const { data: scan, error } = await ctx.admin
        .from("scans")
        .insert({
          userId: ctx.user.id,
          targetUrl: input.targetUrl,
          scanLevel: input.scanLevel,
          scanType: input.scanType,
          status: "queued",
        })
        .select()
        .single();

      if (error) {
        throw internalError("ScanRouter", error);
      }

      return scan;
    }),

  list: protectedProcedure
    .input(
      z.object({
        limit: z.number().min(1).max(100).default(10),
        cursor: z.string().optional(),
      })
    )
    .query(async ({ ctx, input }) => {
      const { limit, cursor } = input;
      let query = ctx.admin
        .from("scans")
        .select("*")
        .eq("userId", ctx.user.id)
        .order("createdAt", { ascending: false })
        .limit(limit + 1);

      if (cursor) {
        query = query.lt("createdAt", cursor);
      }

      const { data, error } = await query;

      if (error) {
        throw internalError("ScanRouter", error);
      }

      const hasMore = data.length > limit;
      const items = hasMore ? data.slice(0, limit) : data;
      const nextCursor = hasMore ? items[items.length - 1].createdAt : null;

      return { items, nextCursor };
    }),

  byId: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ ctx, input }) => {
      const { data: scan, error } = await ctx.admin
        .from("scans")
        .select("*, vulnerabilities(*)")
        .eq("id", input.id)
        .eq("userId", ctx.user.id)
        .single();

      if (error) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });
      }
      return scan;
    }),

  getVulnerabilities: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ ctx, input }) => {
      const { data: scan } = await ctx.admin
        .from("scans")
        .select("id")
        .eq("id", input.scanId)
        .eq("userId", ctx.user.id)
        .single();

      if (!scan) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });
      }

      const { data, error } = await ctx.admin
        .from("vulnerabilities")
        .select("*")
        .eq("scanId", input.scanId)
        .order("createdAt", { ascending: false });

      if (error) {
        throw internalError("ScanRouter", error);
      }
      // Sort by real severity rank (critical first) instead of alphabetical.
      return (data ?? []).sort(bySeverityRank);
    }),

  diff: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ ctx, input }) => {
      // Current scan (ownership-scoped) with its findings.
      const { data: current, error: curErr } = await ctx.admin
        .from("scans")
        .select(
          "id, targetUrl, createdAt, status, vulnerabilities(severity, category, title, affectedUrl)"
        )
        .eq("id", input.scanId)
        .eq("userId", ctx.user.id)
        .single();
      if (curErr || !current) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });
      }

      // Most recent COMPLETED scan of the same target before this one.
      const { data: previous } = await ctx.admin
        .from("scans")
        .select("id, createdAt, vulnerabilities(severity, category, title, affectedUrl)")
        .eq("userId", ctx.user.id)
        .eq("targetUrl", current.targetUrl)
        .eq("status", "completed")
        .lt("createdAt", current.createdAt)
        .order("createdAt", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (!previous) {
        return { hasBaseline: false } as const;
      }

      const diff = diffFindings(
        (previous.vulnerabilities as FindingLike[]) ?? [],
        (current.vulnerabilities as FindingLike[]) ?? []
      );
      return {
        hasBaseline: true as const,
        baselineCreatedAt: previous.createdAt as string,
        addedCount: diff.added.length,
        resolvedCount: diff.resolved.length,
        persistedCount: diff.persisted.length,
      };
    }),
});
