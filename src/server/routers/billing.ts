import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { createTRPCRouter, protectedProcedure } from "@/lib/trpc";
import { createCheckoutSession, createBillingPortalSession } from "@/server/services/billing";

export const billingRouter = createTRPCRouter({
  createCheckout: protectedProcedure
    .input(z.object({ priceId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      try {
        const result = await createCheckoutSession(ctx.user.id, input.priceId);
        return result;
      } catch (err) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: err instanceof Error ? err.message : "Failed to create checkout session",
        });
      }
    }),

  createPortal: protectedProcedure
    .mutation(async ({ ctx }) => {
      try {
        const result = await createBillingPortalSession(ctx.user.id);
        return result;
      } catch (err) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: err instanceof Error ? err.message : "Failed to create portal session",
        });
      }
    }),

  getCurrentPlan: protectedProcedure
    .query(async ({ ctx }) => {
      const { data: user } = await ctx.admin
        .from("users")
        .select("plan, stripeCustomerId")
        .eq("id", ctx.user.id)
        .single();

      if (!user) {
        throw new TRPCError({ code: "NOT_FOUND", message: "User not found" });
      }

      return { plan: user.plan, hasStripeCustomer: !!user.stripeCustomerId };
    }),
});
