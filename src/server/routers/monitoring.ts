import { z } from "zod";
import { createTRPCRouter, protectedProcedure } from "@/lib/trpc";
import { createAdminClient } from "@/lib/supabase/admin";
import { TRPCError } from "@trpc/server";

const ASSET_LIMITS: Record<string, number> = {
  free: 1,
  pro: 10,
  enterprise: 100,
};

export const monitoringRouter = createTRPCRouter({
  list: protectedProcedure.query(async ({ ctx }) => {
    const admin = createAdminClient();
    const { data } = await admin
      .from("monitored_assets")
      .select("*, lastScan:lastScanId(id, status, overallScore, completedAt)")
      .eq("userId", ctx.user.id)
      .order("createdAt", { ascending: false });
    return data || [];
  }),

  create: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      scanType: z.enum(["website", "api", "infrastructure"]).default("website"),
      scanLevel: z.enum(["quick", "standard", "deep"]).default("standard"),
    }))
    .mutation(async ({ ctx, input }) => {
      const admin = createAdminClient();

      // Check plan limits
      const { data: profile } = await admin
        .from("users")
        .select("plan")
        .eq("id", ctx.user.id)
        .single();
      const plan = (profile?.plan as string) || "free";
      const limit = ASSET_LIMITS[plan] || 1;

      const { count } = await admin
        .from("monitored_assets")
        .select("*", { count: "exact", head: true })
        .eq("userId", ctx.user.id)
        .eq("isActive", true);

      if (count && count >= limit) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: `Your plan (${plan}) allows up to ${limit} monitored assets.`,
        });
      }

      const { data, error } = await admin
        .from("monitored_assets")
        .insert({
          userId: ctx.user.id,
          targetUrl: input.targetUrl,
          scanType: input.scanType,
          scanLevel: input.scanLevel,
        })
        .select()
        .single();

      if (error) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
      return data;
    }),

  delete: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const admin = createAdminClient();
      const { error } = await admin
        .from("monitored_assets")
        .delete()
        .eq("id", input.id)
        .eq("userId", ctx.user.id);
      if (error) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
      return { success: true };
    }),
});
