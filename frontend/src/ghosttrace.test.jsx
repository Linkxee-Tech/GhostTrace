import React from "react";
import { render, screen } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import GhostTraceApp from "./GhostTrace.jsx";

describe("GhostTraceApp", () => {
  it("renders the main title", () => {
    render(<GhostTraceApp />);
    expect(screen.getAllByText(/GhostTrace/i).length).toBeGreaterThan(0);
  });

  it("contains scanner endpoint wiring in source", () => {
    const fileScannerSrc = readFileSync(resolve(process.cwd(), "src/components/FileScanner.jsx"), "utf8");
    const urlScannerSrc = readFileSync(resolve(process.cwd(), "src/components/URLScanner.jsx"), "utf8");
    const logAnalyzerSrc = readFileSync(resolve(process.cwd(), "src/components/LogAnalyzer.jsx"), "utf8");
    expect(fileScannerSrc).toContain("/api/analyze-file");
    expect(fileScannerSrc).toContain("/api/generate-report");
    expect(urlScannerSrc).toContain("/api/analyze-url");
    expect(urlScannerSrc).toContain("/api/generate-url-report");
    expect(logAnalyzerSrc).toContain("/api/analyze-log");
    expect(logAnalyzerSrc).toContain("/api/generate-log-report");
  });

  it("keeps fallback/static paths for non-connected pages visible", () => {
    const constantsSrc = readFileSync(resolve(process.cwd(), "src/components/SOCConstants.js"), "utf8");
    const reportsSrc = readFileSync(resolve(process.cwd(), "src/components/Reports.jsx"), "utf8");
    expect(constantsSrc).toContain("export const HISTORY = [");
    expect(reportsSrc).toContain("function Reports({ reportsData = null, setView })");
  });
});
