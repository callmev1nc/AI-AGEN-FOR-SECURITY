-- SecureScan Migration v2
-- Adds new fields to vulnerabilities table for code scanning and fix suggestions

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'vulnerabilities' AND column_name = 'suggestedFix'
  ) THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "suggestedFix" TEXT;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'vulnerabilities' AND column_name = 'filePath'
  ) THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "filePath" TEXT;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'vulnerabilities' AND column_name = 'lineStart'
  ) THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "lineStart" INTEGER;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'vulnerabilities' AND column_name = 'lineEnd'
  ) THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "lineEnd" INTEGER;
  END IF;
END $$;
