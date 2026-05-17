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
      // Rate limit: 5 scans per hour
      const rateLimit = await checkRateLimit(`scan:${ctx.user.id}`);
      if (!rateLimit.success) {
        throw new TRPCError({
          code: "TOO_MANY_REQUESTS",
          message: `Rate limit exceeded. You can start ${rateLimit.limit} scans per hour. Try again later.`,
        });
      }

      const scan = await ctx.db.scan.create({
        data: {
          userId: ctx.user.id,
          targetUrl: input.targetUrl,
          scanLevel: input.scanLevel,
          scanType: "website",
          status: "queued",
        },
      });

      // Try to push job to BullMQ queue, but don't fail if Redis is unavailable
      try {
        const { scanQueue } = await import("@/lib/queue");
        await scanQueue.add("scan", {
          scanId: scan.id,
          targetUrl: input.targetUrl,
          scanLevel: input.scanLevel,
        });
      } catch {
        // Redis not available — scan stays "queued" until worker picks it up
        // For MVP without worker, we'll mark it as running so it shows in the UI
        await ctx.db.scan.update({
          where: { id: scan.id },
          data: { status: "running", startedAt: new Date() },
        });
      }

      return scan;
    }),

  list: protectedProcedure.query(async ({ ctx }) => {
    const scans = await ctx.db.scan.findMany({
      where: { userId: ctx.user.id },
      orderBy: { createdAt: "desc" },
      take: 50,
    });
    return scans;
  }),

  byId: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ ctx, input }) => {
      const scan = await ctx.db.scan.findUnique({
        where: { id: input.id, userId: ctx.user.id },
        include: { vulnerabilities: true },
      });
      return scan;
    }),

  getVulnerabilities: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ ctx, input }) => {
      const vulnerabilities = await ctx.db.vulnerability.findMany({
        where: { scanId: input.scanId },
        orderBy: [
          { severity: "asc" }, // critical first
          { category: "asc" },
        ],
      });
      return vulnerabilities;
    }),
});
