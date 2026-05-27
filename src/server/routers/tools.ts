import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { createTRPCRouter, protectedProcedure } from "@/lib/trpc";
import { checkRateLimit } from "@/lib/rate-limit";
import { logger } from "@/lib/logger";

import { analyzePhishing } from "@/server/services/tools/phishing-analyzer";
import { explainCve } from "@/server/services/tools/cve-explainer";
import { scanSecrets } from "@/server/services/tools/secrets-scanner";
import { generateFirewallRules } from "@/server/services/tools/firewall-rules";
import { auditPasswordPolicy } from "@/server/services/tools/password-auditor";
import { generateEthicalPayloads } from "@/server/services/tools/ethical-payload-generator";
import { analyzeHeaders } from "@/server/services/tools/headers-analyzer";

export const toolsRouter = createTRPCRouter({
  phishingAnalyzer: protectedProcedure
    .input(z.object({ emailText: z.string().min(1, "Email text is required").max(50000) }))
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`tools:phishing:${ctx.user.id}`, "free");
      if (!rateLimit.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Try again later." });
      }
      const result = await analyzePhishing(input.emailText);
      const { error } = await ctx.admin.from("tool_results").insert({
        userId: ctx.user.id,
        toolType: "phishing-analyzer",
        input: { emailText: input.emailText },
        output: result,
      });
      if (error) { logger.error("ToolsRouter", `Failed to save phishing result: ${error.message}`); throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to save result" }); }
      return result;
    }),

  cveExplainer: protectedProcedure
    .input(z.object({ cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i, "Invalid CVE ID format (e.g. CVE-2024-12345)") }))
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`tools:cve:${ctx.user.id}`, "free");
      if (!rateLimit.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Try again later." });
      }
      const result = await explainCve(input.cveId.toUpperCase());
      const { error } = await ctx.admin.from("tool_results").insert({
        userId: ctx.user.id,
        toolType: "cve-explainer",
        input: { cveId: input.cveId },
        output: result,
      });
      if (error) { logger.error("ToolsRouter", `Failed to save CVE result: ${error.message}`); throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to save result" }); }
      return result;
    }),

  secretsScanner: protectedProcedure
    .input(z.object({ content: z.string().min(1, "Content is required").max(50000) }))
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`tools:secrets:${ctx.user.id}`, "free");
      if (!rateLimit.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Try again later." });
      }
      const result = await scanSecrets(input.content);
      const { error } = await ctx.admin.from("tool_results").insert({
        userId: ctx.user.id,
        toolType: "secrets-scanner",
        input: { contentLength: input.content.length },
        output: result,
      });
      if (error) { logger.error("ToolsRouter", `Failed to save secrets result: ${error.message}`); throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to save result" }); }
      return result;
    }),

  firewallRules: protectedProcedure
    .input(z.object({
      description: z.string().min(1, "Description is required").max(5000),
      platform: z.enum(["iptables", "ufw", "aws"]),
    }))
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`tools:firewall:${ctx.user.id}`, "free");
      if (!rateLimit.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Try again later." });
      }
      const result = await generateFirewallRules(input.description, input.platform);
      const { error } = await ctx.admin.from("tool_results").insert({
        userId: ctx.user.id,
        toolType: "firewall-rules",
        input: { description: input.description, platform: input.platform },
        output: result,
      });
      if (error) { logger.error("ToolsRouter", `Failed to save firewall result: ${error.message}`); throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to save result" }); }
      return result;
    }),

  passwordAuditor: protectedProcedure
    .input(z.object({ policyText: z.string().min(1, "Policy text is required").max(50000) }))
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`tools:password:${ctx.user.id}`, "free");
      if (!rateLimit.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Try again later." });
      }
      const result = await auditPasswordPolicy(input.policyText);
      const { error } = await ctx.admin.from("tool_results").insert({
        userId: ctx.user.id,
        toolType: "password-auditor",
        input: { policyText: input.policyText },
        output: result,
      });
      if (error) { logger.error("ToolsRouter", `Failed to save password result: ${error.message}`); throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to save result" }); }
      return result;
    }),

  payloadGenerator: protectedProcedure
    .input(z.object({
      endpointDescription: z.string().min(1, "Endpoint description is required").max(5000),
      endpointType: z.enum(["rest", "web-form", "graphql"]),
      vulnerabilityTypes: z.array(z.enum(["sql-injection", "xss", "path-traversal", "command-injection", "nosql-injection", "ldap-injection", "xxe", "ssrf"])).min(1, "Select at least one vulnerability type"),
    }))
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`tools:payload:${ctx.user.id}`, "free");
      if (!rateLimit.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Try again later." });
      }
      const result = await generateEthicalPayloads(
        input.endpointDescription,
        input.endpointType,
        input.vulnerabilityTypes
      );
      const { error } = await ctx.admin.from("tool_results").insert({
        userId: ctx.user.id,
        toolType: "payload-generator",
        input: {
          endpointDescription: input.endpointDescription,
          endpointType: input.endpointType,
          vulnerabilityTypes: input.vulnerabilityTypes,
        },
        output: result,
      });
      if (error) { logger.error("ToolsRouter", `Failed to save payload result: ${error.message}`); throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to save result" }); }
      return result;
    }),

  headersAnalyzer: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url("Invalid URL").refine((url) => {
        try {
          const parsed = new URL(url);
          const host = parsed.hostname;
          if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0") return false;
          if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return false;
          if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
          return true;
        } catch {
          return false;
        }
      }, "Scanning private/local addresses is not allowed"),
    }))
    .mutation(async ({ ctx, input }) => {
      const rateLimit = await checkRateLimit(`tools:headers:${ctx.user.id}`, "free");
      if (!rateLimit.success) {
        throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Rate limit exceeded. Try again later." });
      }
      const result = await analyzeHeaders(input.targetUrl);
      const { error } = await ctx.admin.from("tool_results").insert({
        userId: ctx.user.id,
        toolType: "headers-analyzer",
        input: { targetUrl: input.targetUrl },
        output: result,
      });
      if (error) { logger.error("ToolsRouter", `Failed to save headers result: ${error.message}`); throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to save result" }); }
      return result;
    }),
});
