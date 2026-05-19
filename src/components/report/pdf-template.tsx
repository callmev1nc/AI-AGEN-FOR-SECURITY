import React from "react";
import {
  Document,
  Page,
  Text,
  View,
  StyleSheet,
  Font,
} from "@react-pdf/renderer";

Font.register({
  family: "JetBrains",
  fonts: [
    {
      src: "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxDcwg.woff2",
      fontWeight: 400,
    },
    {
      src: "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxDcwg.woff2",
      fontWeight: 700,
    },
  ],
});

const styles = StyleSheet.create({
  page: {
    backgroundColor: "#06080d",
    color: "#e2e8f0",
    padding: 40,
    fontFamily: "Helvetica",
    fontSize: 10,
  },
  header: {
    marginBottom: 30,
    borderBottomWidth: 1,
    borderBottomColor: "#1e2a3a",
    paddingBottom: 20,
  },
  logo: {
    fontFamily: "JetBrains",
    fontSize: 20,
    fontWeight: 700,
    color: "#10b981",
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 10,
    color: "#64748b",
  },
  scoreSection: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 30,
    padding: 20,
    backgroundColor: "#111621",
    borderRadius: 8,
  },
  scoreCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    borderWidth: 4,
    borderColor: "#10b981",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 20,
  },
  scoreNumber: {
    fontFamily: "JetBrains",
    fontSize: 28,
    fontWeight: 700,
    color: "#10b981",
  },
  scoreLabel: {
    fontSize: 14,
    fontWeight: 700,
    color: "#10b981",
    marginBottom: 4,
  },
  scoreDetails: {
    fontSize: 9,
    color: "#94a3b8",
  },
  metaRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 20,
  },
  metaItem: {
    backgroundColor: "#111621",
    padding: 12,
    borderRadius: 6,
    flex: 1,
    marginRight: 10,
  },
  metaLabel: {
    fontSize: 8,
    color: "#64748b",
    textTransform: "uppercase",
    marginBottom: 4,
    fontFamily: "JetBrains",
  },
  metaValue: {
    fontSize: 16,
    fontWeight: 700,
    fontFamily: "JetBrains",
  },
  sectionTitle: {
    fontFamily: "JetBrains",
    fontSize: 12,
    fontWeight: 700,
    color: "#10b981",
    marginTop: 20,
    marginBottom: 10,
    textTransform: "uppercase",
  },
  vulnCard: {
    backgroundColor: "#111621",
    borderRadius: 6,
    padding: 14,
    marginBottom: 8,
    borderLeftWidth: 3,
    borderLeftColor: "#ef4444",
  },
  vulnHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 6,
  },
  vulnTitle: {
    fontSize: 11,
    fontWeight: 700,
    flex: 1,
  },
  severityBadge: {
    fontSize: 8,
    fontFamily: "JetBrains",
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 3,
    textTransform: "uppercase",
  },
  critical: { backgroundColor: "#ef444433", color: "#ef4444" },
  high: { backgroundColor: "#f9731633", color: "#f97316" },
  medium: { backgroundColor: "#f59e0b33", color: "#f59e0b" },
  low: { backgroundColor: "#3b82f633", color: "#3b82f6" },
  info: { backgroundColor: "#8b5cf633", color: "#8b5cf6" },
  vulnText: {
    fontSize: 9,
    color: "#94a3b8",
    lineHeight: 1.5,
    marginBottom: 4,
  },
  vulnLabel: {
    fontSize: 8,
    color: "#64748b",
    textTransform: "uppercase",
    fontFamily: "JetBrains",
    marginTop: 6,
    marginBottom: 2,
  },
  remediation: {
    fontSize: 9,
    color: "#10b981",
    lineHeight: 1.4,
  },
  footer: {
    position: "absolute",
    bottom: 30,
    left: 40,
    right: 40,
    borderTopWidth: 1,
    borderTopColor: "#1e2a3a",
    paddingTop: 10,
    flexDirection: "row",
    justifyContent: "space-between",
    fontSize: 8,
    color: "#64748b",
  },
});

interface Vulnerability {
  severity: string;
  category: string;
  title: string;
  description: string;
  evidence?: string;
  remediation: string;
  affectedUrl: string;
}

interface ReportProps {
  targetUrl: string;
  scanLevel: string;
  overallScore: number;
  date: string;
  vulnerabilities: Vulnerability[];
}

function getScoreColor(score: number): string {
  if (score >= 80) return "#10b981";
  if (score >= 50) return "#f59e0b";
  return "#ef4444";
}

function getScoreLabel(score: number): string {
  if (score >= 80) return "Good";
  if (score >= 50) return "Needs Attention";
  return "Critical Risk";
}

export function SecurityReport({
  targetUrl,
  scanLevel,
  overallScore,
  date,
  vulnerabilities,
}: ReportProps) {
  const scoreColor = getScoreColor(overallScore);
  const counts = {
    critical: vulnerabilities.filter((v) => v.severity === "critical").length,
    high: vulnerabilities.filter((v) => v.severity === "high").length,
    medium: vulnerabilities.filter((v) => v.severity === "medium").length,
    low: vulnerabilities.filter((v) => v.severity === "low").length,
    info: vulnerabilities.filter((v) => v.severity === "info").length,
  };

  return (
    <Document>
      <Page size="A4" style={styles.page}>
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.logo}>SecureScan</Text>
          <Text style={styles.subtitle}>Security Audit Report</Text>
        </View>

        {/* Score */}
        <View style={[styles.scoreSection, { borderColor: scoreColor }]}>
          <View style={[styles.scoreCircle, { borderColor: scoreColor }]}>
            <Text style={[styles.scoreNumber, { color: scoreColor }]}>
              {overallScore}
            </Text>
          </View>
          <View>
            <Text style={[styles.scoreLabel, { color: scoreColor }]}>
              {getScoreLabel(overallScore)}
            </Text>
            <Text style={styles.scoreDetails}>
              {vulnerabilities.length} findings across {scanLevel} scan
            </Text>
            <Text style={styles.scoreDetails}>{targetUrl}</Text>
          </View>
        </View>

        {/* Severity counts */}
        <View style={styles.metaRow}>
          <View style={styles.metaItem}>
            <Text style={styles.metaLabel}>Critical</Text>
            <Text style={[styles.metaValue, { color: "#ef4444" }]}>
              {counts.critical}
            </Text>
          </View>
          <View style={[styles.metaItem, { marginHorizontal: 10 }]}>
            <Text style={styles.metaLabel}>High</Text>
            <Text style={[styles.metaValue, { color: "#f97316" }]}>
              {counts.high}
            </Text>
          </View>
          <View style={[styles.metaItem, { marginRight: 10 }]}>
            <Text style={styles.metaLabel}>Medium</Text>
            <Text style={[styles.metaValue, { color: "#f59e0b" }]}>
              {counts.medium}
            </Text>
          </View>
          <View style={styles.metaItem}>
            <Text style={styles.metaLabel}>Low / Info</Text>
            <Text style={[styles.metaValue, { color: "#3b82f6" }]}>
              {counts.low + counts.info}
            </Text>
          </View>
        </View>

        {/* Vulnerability list */}
        <Text style={styles.sectionTitle}>Findings</Text>
        {vulnerabilities.map((vuln, i) => (
          <View
            key={i}
            style={[
              styles.vulnCard,
              {
                borderLeftColor:
                  vuln.severity === "critical"
                    ? "#ef4444"
                    : vuln.severity === "high"
                    ? "#f97316"
                    : vuln.severity === "medium"
                    ? "#f59e0b"
                    : vuln.severity === "low"
                    ? "#3b82f6"
                    : "#8b5cf6",
              },
            ]}
          >
            <View style={styles.vulnHeader}>
              <Text style={styles.vulnTitle}>{vuln.title}</Text>
              <Text
                style={[
                  styles.severityBadge,
                  styles[vuln.severity as keyof typeof styles] ||
                    styles.info,
                ]}
              >
                {vuln.severity}
              </Text>
            </View>
            <Text style={styles.vulnText}>{vuln.description}</Text>
            {vuln.evidence && (
              <>
                <Text style={styles.vulnLabel}>Evidence</Text>
                <Text style={styles.vulnText}>{vuln.evidence}</Text>
              </>
            )}
            <Text style={styles.vulnLabel}>Remediation</Text>
            <Text style={styles.remediation}>{vuln.remediation}</Text>
          </View>
        ))}

        {/* Footer */}
        <View style={styles.footer}>
          <Text>SecureScan — Automated Security Audit Report</Text>
          <Text>Generated: {date}</Text>
        </View>
      </Page>
    </Document>
  );
}
