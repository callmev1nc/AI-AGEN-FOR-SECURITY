import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { createTRPCRouter, protectedProcedure } from "@/lib/trpc";
import { answerSecurityQuestion } from "@/server/services/rag-pipeline";
import { checkRateLimit } from "@/lib/rate-limit";

export const chatRouter = createTRPCRouter({
  sendMessage: protectedProcedure
    .input(
      z.object({
        scanId: z.string(),
        message: z.string().min(1).max(2000),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const rateResult = await checkRateLimit(`chat:${ctx.user.id}`, "free");
      if (!rateResult.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Please wait before sending more messages." });
      }
      const result = await answerSecurityQuestion(
        input.message,
        input.scanId,
        ctx.user.id
      );
      return result;
    }),

  getHistory: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ ctx, input }) => {
      const { data, error } = await ctx.admin
        .from("chat_messages")
        .select("*")
        .eq("scan_id", input.scanId)
        .eq("user_id", ctx.user.id)
        .order("created_at", { ascending: true })
        .limit(50);

      if (error) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: error.message });
      }

      return data;
    }),
});
