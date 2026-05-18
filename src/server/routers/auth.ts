import { createTRPCRouter, protectedProcedure } from "@/lib/trpc";

export const authRouter = createTRPCRouter({
  me: protectedProcedure.query(async ({ ctx }) => {
    const { data } = await ctx.admin
      .from("users")
      .select("*")
      .eq("id", ctx.user.id)
      .single();
    return data;
  }),
});
