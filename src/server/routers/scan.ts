import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { createTRPCRouter, protectedProcedure } from "@/lib/trpc";
import { checkRateLimit } from "@/lib/rate-limit";

export const scanRouter = createTRPCRouter({
  create: protectedProcedure
    .input(
      z.object({
        targetUrl: z.string().url("Invalid URL"),
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

      // Try BullMQ queue, fall back to marking as running
      try {
        const { scanQueue } = await import("@/lib/queue");
        await scanQueue.add("scan", {
          scanId: scan.id,
          targetUrl: input.targetUrl,
          scanLevel: input.scanLevel,
        });
      } catch {
        await ctx.admin
          .from("scans")
          .update({ status: "running", startedAt: new Date().toISOString() })
          .eq("id", scan.id);
      }

      return scan;
    }),

  list: protectedProcedure.query(async ({ ctx }) => {
    const { data, error } = await ctx.admin
      .from("scans")
      .select("*")
      .eq("userId", ctx.user.id)
      .order("createdAt", { ascending: false })
      .limit(50);

    if (error) {
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
    }
    return data;
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
      // Verify the scan belongs to the user
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
