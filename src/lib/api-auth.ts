import { createHash } from "crypto";
import { createAdminClient } from "@/lib/supabase/admin";

export class ApiAuthError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
    this.name = "ApiAuthError";
  }
}

function hashKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export function generateApiKey(): { plaintext: string; keyHash: string; keyPrefix: string } {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const randomBytes = new Uint8Array(42);
  crypto.getRandomValues(randomBytes);
  const secret = Array.from(randomBytes, (b) => chars[b % chars.length]).join("");
  const plaintext = `ssc_live_${secret}`;
  return {
    plaintext,
    keyHash: hashKey(plaintext),
    keyPrefix: plaintext.slice(0, 12),
  };
}

export async function authenticateApiKey(req: Request): Promise<{
  userId: string;
  keyId: string;
}> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new ApiAuthError(401, "Missing or invalid Authorization header");
  }

  const key = authHeader.slice("Bearer ".length).trim();
  const keyHash = hashKey(key);

  const admin = createAdminClient();
  const { data: keyRecord, error } = await admin
    .from("api_keys")
    .select("id, userId, revokedAt")
    .eq("keyHash", keyHash)
    .single();

  if (error || !keyRecord) {
    throw new ApiAuthError(401, "Invalid API key");
  }

  if (keyRecord.revokedAt) {
    throw new ApiAuthError(401, "API key has been revoked");
  }

  // Update last used info
  const forwardedFor = req.headers.get("x-forwarded-for");
  const ip = forwardedFor?.split(",")[0]?.trim() || "unknown";

  await admin
    .from("api_keys")
    .update({ lastUsedAt: new Date().toISOString(), lastIp: ip })
    .eq("id", keyRecord.id);

  return { userId: keyRecord.userId, keyId: keyRecord.id };
}
