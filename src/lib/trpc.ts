import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import { createClient as createSupabaseClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { logger } from "@/lib/logger";

export async function createTRPCContext() {
  const supabase = await createSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const admin = createAdminClient();

  return { admin, supabase, user };
}

const t = initTRPC.context<typeof createTRPCContext>().create({
  transformer: superjson,
});

export const createTRPCRouter = t.router;
export const createCallerFactory = t.createCallerFactory;

export const publicProcedure = t.procedure;

export const protectedProcedure = t.procedure.use(async ({ ctx, next }) => {
  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED" });
  }
  return next({
    ctx: { ...ctx, user: ctx.user },
  });
});

/**
 * Log an unexpected/internal error server-side (full detail) and return a
 * TRPCError with a GENERIC user-facing message. Use this instead of
 * `new TRPCError({ message: error.message })`, which leaks DB/internals
 * (table names, constraint names, etc.) to the client.
 */
export function internalError(tag: string, error: unknown): TRPCError {
  const detail = error instanceof Error ? error.message : String(error);
  logger.error(tag, `Internal error: ${detail}`);
  return new TRPCError({
    code: "INTERNAL_SERVER_ERROR",
    message: "Something went wrong. Please try again.",
  });
}
