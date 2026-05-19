import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { createTRPCRouter, protectedProcedure } from "@/lib/trpc";
import { checkRateLimit } from "@/lib/rate-limit";
import { generatePdfReport } from "@/server/services/report";

export const scanRouter = createTRPCRouter({
  listReports: protectedProcedure.query(async ({ ctx }) => {
    const { data, error } = await ctx.admin
      .from("reports")
      .select("id, scanId, format, storagePath, createdAt, scans(targetUrl, overallScore)")
      .eq("userId", ctx.user.id)
      .order("createdAt", { ascending: false })
      .limit(50);

    if (error) {
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
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
  create: protectedProcedure
    .input(
      z.object({
        targetUrl: z.string().url("Invalid URL").refine((url) => {
          try {
            const parsed = new URL(url);
            const host = parsed.hostname;
            if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0") return false;
            if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return false;
            if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
            return true;
          } catch {
            return false;
          }
        }, "Scanning private/local addresses is not allowed"),
        scanLevel: z.enum(["quick", "standard", "deep"]).default("standard"),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`scan:${ctx.user.id}`);
      if (!rateLimit.success) {
        throw new TRPCError({
          code: "TOO_MANY_REQUESTS",
          message: `Rate limit exceeded. You can start ${rateLimit.limit} scans per hour. Try again later.`,
        });
      }

      const { data: scan, error } = await ctx.admin
        .from("scans")
        .insert({
          userId: ctx.user.id,
          targetUrl: input.targetUrl,
          scanLevel: input.scanLevel,
          scanType: "website",
          status: "queued",
        })
        .select()
        .single();

      if (error) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
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
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
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
        .order("severity", { ascending: true });

      if (error) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
      }
      return data;
    }),
});
