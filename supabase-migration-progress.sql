-- Migration: Add progress tracking fields to scans table
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor)

ALTER TABLE "scans"
  ADD COLUMN "progressPercent" INTEGER,
  ADD COLUMN "currentModule" TEXT,
  ADD COLUMN "modulesCompleted" INTEGER,
  ADD COLUMN "totalModules" INTEGER,
  ADD COLUMN "errorMessage" TEXT;
