import { createAdminClient } from "@/lib/supabase/admin";
import { logger } from "@/lib/logger";
import { createHmac } from "crypto";

interface AlertEvent {
  id: string;
  assetId: string;
  scanId: string;
  newCriticalCount: number;
  channelId: string | null;
}

interface Channel {
  id: string;
  userId: string;
  type: "email" | "slack" | "webhook";
  config: Record<string, unknown>;
  isActive: boolean;
}

function hmacSha256(secret: string, body: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

async function sendEmail(alert: AlertEvent, channel: Channel): Promise<boolean> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    logger.error("Notify", "RESEND_API_KEY not set, skipping email");
    return false;
  }

  const to = channel.config.to as string;
  const assetId = alert.assetId;

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "SecureScan <alerts@securescan.app>",
        to,
        subject: `[SecureScan] ${alert.newCriticalCount} new critical findings for asset ${assetId}`,
        text: `Scan ${alert.scanId} completed with ${alert.newCriticalCount} new critical findings.`,
      }),
    });
    return res.ok;
  } catch (err) {
    logger.error("Notify", `Email send failed: ${err}`);
    return false;
  }
}

async function sendSlack(alert: AlertEvent, channel: Channel): Promise<boolean> {
  const webhookUrl = channel.config.webhookUrl as string;
  if (!webhookUrl) return false;

  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        blocks: [
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `*SecureScan Alert*\n${alert.newCriticalCount} new critical finding(s) in scan <https://securescan.app/dashboard/scans/${alert.scanId}|${alert.scanId}>`,
            },
          },
        ],
      }),
    });
    return res.ok;
  } catch (err) {
    logger.error("Notify", `Slack send failed: ${err}`);
    return false;
  }
}

async function sendWebhook(alert: AlertEvent, channel: Channel): Promise<boolean> {
  const url = channel.config.url as string;
  const secret = channel.config.secret as string || "";
  if (!url) return false;

  const body = JSON.stringify({
    event: "scan.alert",
    scanId: alert.scanId,
    assetId: alert.assetId,
    newCriticalCount: alert.newCriticalCount,
    timestamp: new Date().toISOString(),
  });

  const signature = hmacSha256(secret, body);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-SecureScan-Signature": signature,
      },
      body,
    });
    return res.ok;
  } catch (err) {
    logger.error("Notify", `Webhook send failed: ${err}`);
    return false;
  }
}

export async function deliverAlert(
  alert: AlertEvent,
  channel: Channel
): Promise<boolean> {
  switch (channel.type) {
    case "email":
      return sendEmail(alert, channel);
    case "slack":
      return sendSlack(alert, channel);
    case "webhook":
      return sendWebhook(alert, channel);
    default:
      return false;
  }
}

export async function notifyNewCriticalFindings(
  scanId: string,
  assetId: string,
  newCriticalCount: number
): Promise<void> {
  if (newCriticalCount <= 0) return;

  const admin = createAdminClient();

  // Resolve the asset's owner so alerts are delivered ONLY to that user's
  // channels. Without this scoping, a critical-finding alert for one asset
  // would be sent to every user's configured Slack / email / webhook.
  const { data: asset } = await admin
    .from("monitored_assets")
    .select("userId")
    .eq("id", assetId)
    .single();

  if (!asset) return;

  const { data: channels } = await admin
    .from("alert_channels")
    .select("*")
    .eq("userId", asset.userId)
    .eq("isActive", true);

  if (!channels || channels.length === 0) return;

  const alertEvent = {
    id: crypto.randomUUID(),
    assetId,
    scanId,
    newCriticalCount,
    channelId: null,
  };

  for (const channel of channels as Channel[]) {
    const delivered = await deliverAlert(alertEvent, channel);
    await admin.from("alert_events").insert({
      assetId,
      scanId,
      newCriticalCount,
      delivered,
      channelId: channel.id,
    });
    logger.info("Notify", `Alert ${alertEvent.id} delivered=${delivered} via ${channel.type}`);
  }
}
