import { render, screen } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import GhostTraceApp from "./GhostTrace.jsx";

describe("GhostTraceApp", () => {
  it("renders the main title", () => {
    render(<GhostTraceApp />);
    expect(screen.getByText(/GhostTrace/i)).toBeTruthy();
  });

  it("contains scanner endpoint wiring in source", () => {
    const src = readFileSync(resolve(process.cwd(), "src/GhostTrace.jsx"), "utf8");
    expect(src).toContain("/api/analyze-file");
    expect(src).toContain("/api/generate-report");
    expect(src).toContain("/api/analyze-url");
    expect(src).toContain("/api/generate-url-report");
    expect(src).toContain("/api/analyze-log");
    expect(src).toContain("/api/generate-log-report");
  });

  it("keeps fallback/static paths for non-connected pages visible", () => {
    const src = readFileSync(resolve(process.cwd(), "src/GhostTrace.jsx"), "utf8");
    expect(src).toContain("const HISTORY = [");
    expect(src).toContain("function Reports({ reportsData = null })");
  });
});
