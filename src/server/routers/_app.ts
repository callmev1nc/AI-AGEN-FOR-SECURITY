import { createTRPCRouter } from "@/lib/trpc";
import { authRouter } from "./auth";
import { scanRouter } from "./scan";
import { chatRouter } from "./chat";
import { billingRouter } from "./billing";

export const appRouter = createTRPCRouter({
  auth: authRouter,
  scan: scanRouter,
  chat: chatRouter,
  billing: billingRouter,
});

export type AppRouter = typeof appRouter;
