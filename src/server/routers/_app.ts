import { createTRPCRouter } from "@/lib/trpc";
import { authRouter } from "./auth";
import { scanRouter } from "./scan";

export const appRouter = createTRPCRouter({
  auth: authRouter,
  scan: scanRouter,
});

export type AppRouter = typeof appRouter;
