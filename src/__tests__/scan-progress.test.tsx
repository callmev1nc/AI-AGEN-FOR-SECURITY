import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

// Mock next/navigation
vi.mock("next/navigation", () => ({
  useParams: () => ({ id: "test-scan-id" }),
  useRouter: () => ({ push: vi.fn() }),
}));

// Mock tRPC client
vi.mock("@/lib/trpc-client", () => ({
  trpcClient: {
    scan: {
      byId: {
        query: vi.fn(),
      },
      exportPdf: {
        mutate: vi.fn(),
      },
      generateAiReport: {
        mutate: vi.fn(),
      },
    },
    chat: {
      getHistory: {
        query: vi.fn().mockResolvedValue([]),
      },
      sendMessage: {
        mutate: vi.fn(),
      },
    },
  },
}));

import ScanResultsPage from "@/app/dashboard/scans/[id]/page";
import { trpcClient } from "@/lib/trpc-client";

const mockScan = (overrides: Record<string, unknown> = {}) => ({
  id: "test-scan-id",
  targetUrl: "https://example.com",
  status: "running",
  scanLevel: "standard",
  overallScore: null,
  progressPercent: 40,
  currentModule: "Security Headers",
  modulesCompleted: 2,
  totalModules: 7,
  errorMessage: null,
  createdAt: new Date().toISOString(),
  vulnerabilities: [],
  ...overrides,
});

describe("ScanResultsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows loading state initially", () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockReturnValue(new Promise(() => {}));

    render(<ScanResultsPage />);
    expect(screen.getByText("Loading scan results...")).toBeInTheDocument();
  });

  it("shows error state when scan is not found", async () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockRejectedValue(new Error("Scan not found"));

    render(<ScanResultsPage />);
    expect(await screen.findByText("Scan not found")).toBeInTheDocument();
  });

  it("shows progress bar when scan is running", async () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockResolvedValue(mockScan({ status: "running", progressPercent: 40 }));

    render(<ScanResultsPage />);
    expect(await screen.findByText("Scan in progress")).toBeInTheDocument();
    expect(await screen.findByText("40%")).toBeInTheDocument();
    expect(await screen.findByText("2 of 7 modules completed")).toBeInTheDocument();
    expect(await screen.findByText("Security Headers")).toBeInTheDocument();
  });

  it("shows queued message when scan is queued, and triggers API call", async () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockResolvedValue(mockScan({ status: "queued", progressPercent: 0, modulesCompleted: 0 }));

    render(<ScanResultsPage />);
    expect(await screen.findByText("Scan queued")).toBeInTheDocument();
    expect(await screen.findByText("Starting scan...")).toBeInTheDocument();
  });

  it("shows error message when scan has error", async () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockResolvedValue(
      mockScan({ status: "running", errorMessage: "Scanner 'Port Scan' failed: Connection timeout" })
    );

    render(<ScanResultsPage />);
    expect(await screen.findByText(/Scanner error/)).toBeInTheDocument();
    expect(await screen.findByText(/Connection timeout/)).toBeInTheDocument();
  });

  it("shows completed results when scan is done", async () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockResolvedValue(
      mockScan({
        status: "completed",
        progressPercent: 100,
        overallScore: 85,
        vulnerabilities: [
          {
            id: "vuln-1",
            severity: "medium",
            category: "SSL/TLS",
            title: "SSL certificate expires within 30 days",
            description: "The SSL certificate expires in 15 days.",
            evidence: null,
            remediation: "Renew the SSL certificate.",
            affectedUrl: "https://example.com",
          },
        ],
      })
    );

    render(<ScanResultsPage />);
    expect(await screen.findByText("Scan Results")).toBeInTheDocument();
    expect(await screen.findByText("85")).toBeInTheDocument();
    expect(await screen.findByText("Good")).toBeInTheDocument();
    expect(await screen.findByText("1 findings total")).toBeInTheDocument();
  });

  it("shows scan target URL and level in the header", async () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockResolvedValue(mockScan({ status: "running" }));

    render(<ScanResultsPage />);
    expect(await screen.findByText(/https:\/\/example.com/)).toBeInTheDocument();
    expect(await screen.findByText(/standard/)).toBeInTheDocument();
  });

  it("refetches scan data when status is running", async () => {
    const queryMock = vi.mocked(trpcClient.scan.byId.query);
    queryMock.mockResolvedValue(mockScan({ status: "running" }));

    render(<ScanResultsPage />);

    expect(await screen.findByText("Scan in progress")).toBeInTheDocument();
    expect(queryMock).toHaveBeenCalledTimes(1);
  });
});
