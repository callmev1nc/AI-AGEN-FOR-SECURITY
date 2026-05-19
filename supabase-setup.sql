-- Security Audit Platform - Database Setup
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor)

-- Enums
CREATE TYPE "Plan" AS ENUM ('free', 'pro', 'enterprise');
CREATE TYPE "ScanStatus" AS ENUM ('queued', 'running', 'completed', 'failed');
CREATE TYPE "ScanType" AS ENUM ('website', 'api', 'infrastructure');
CREATE TYPE "ScanLevel" AS ENUM ('quick', 'standard', 'deep');
CREATE TYPE "Severity" AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE "ReportFormat" AS ENUM ('pdf', 'json', 'html');

-- Users table
CREATE TABLE "users" (
  "id" UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  "email" TEXT NOT NULL UNIQUE,
  "name" TEXT NOT NULL,
  "plan" "Plan" NOT NULL DEFAULT 'free',
  "stripeCustomerId" TEXT UNIQUE,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE "scans" (
  "id" UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  "userId" UUID NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "targetUrl" TEXT NOT NULL,
  "status" "ScanStatus" NOT NULL DEFAULT 'queued',
  "scanType" "ScanType" NOT NULL DEFAULT 'website',
  "scanLevel" "ScanLevel" NOT NULL DEFAULT 'standard',
  "overallScore" INTEGER,
  "startedAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "scans_userId_idx" ON "scans"("userId");
CREATE INDEX "scans_status_idx" ON "scans"("status");

-- Vulnerabilities table
CREATE TABLE "vulnerabilities" (
  "id" UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  "scanId" UUID NOT NULL REFERENCES "scans"("id") ON DELETE CASCADE,
  "severity" "Severity" NOT NULL,
  "category" TEXT NOT NULL,
  "title" TEXT NOT NULL,
  "description" TEXT NOT NULL,
  "evidence" TEXT,
  "remediation" TEXT NOT NULL,
  "cvssScore" DOUBLE PRECISION,
  "affectedUrl" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "vulnerabilities_scanId_idx" ON "vulnerabilities"("scanId");
CREATE INDEX "vulnerabilities_severity_idx" ON "vulnerabilities"("severity");

-- Reports table
CREATE TABLE "reports" (
  "id" UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  "scanId" UUID NOT NULL REFERENCES "scans"("id") ON DELETE CASCADE,
  "userId" UUID NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "format" "ReportFormat" NOT NULL,
  "storagePath" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "reports_userId_idx" ON "reports"("userId");
CREATE INDEX "reports_scanId_idx" ON "reports"("scanId");

-- Enable Row Level Security
ALTER TABLE "users" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "scans" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "vulnerabilities" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "reports" ENABLE ROW LEVEL SECURITY;

-- RLS Policies (users can only access their own data)
CREATE POLICY "Users can view own profile" ON "users" FOR SELECT USING (auth.uid() = "id"::uuid);
CREATE POLICY "Users can update own profile" ON "users" FOR UPDATE USING (auth.uid() = "id"::uuid);

CREATE POLICY "Users can view own scans" ON "scans" FOR SELECT USING (auth.uid() = "userId"::uuid);
CREATE POLICY "Users can create own scans" ON "scans" FOR INSERT WITH CHECK (auth.uid() = "userId"::uuid);
CREATE POLICY "Users can update own scans" ON "scans" FOR UPDATE USING (auth.uid() = "userId"::uuid);

CREATE POLICY "Users can view own vulnerabilities" ON "vulnerabilities" FOR SELECT USING (
  EXISTS (SELECT 1 FROM "scans" WHERE "scans"."id" = "vulnerabilities"."scanId" AND "scans"."userId" = auth.uid())
);

CREATE POLICY "Users can view own reports" ON "reports" FOR SELECT USING (auth.uid() = "userId"::uuid);
CREATE POLICY "Users can create own reports" ON "reports" FOR INSERT WITH CHECK (auth.uid() = "userId"::uuid);

-- Storage: Create reports bucket for PDF exports
INSERT INTO storage.buckets (id, name, public)
VALUES ('reports', 'reports', false)
ON CONFLICT (id) DO NOTHING;

CREATE POLICY "Users can view own report files"
ON storage.objects FOR SELECT
USING (auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can upload own report files"
ON storage.objects FOR INSERT
WITH CHECK (
  auth.uid()::text = (storage.foldername(name))[1]
  AND bucket_id = 'reports'
);

-- Auto-update "updatedAt" trigger for users
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW."updatedAt" = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
  BEFORE UPDATE ON "users"
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();
