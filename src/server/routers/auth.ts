import { z } from "zod";
import { createTRPCRouter, protectedProcedure, internalError } from "@/lib/trpc";

export const authRouter = createTRPCRouter({
  me: protectedProcedure.query(async ({ ctx }) => {
    const { data } = await ctx.admin
      .from("users")
      .select("*")
      .eq("id", ctx.user.id)
      .single();
    return data;
  }),

  updateProfile: protectedProcedure
    .input(
      z.object({
        name: z.string().min(1, "Name is required").max(100),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const { data, error } = await ctx.admin
        .from("users")
        .update({ name: input.name })
        .eq("id", ctx.user.id)
        .select()
        .single();

      if (error) {
        throw internalError("AuthRouter", error);
      }
      return data;
    }),
});
