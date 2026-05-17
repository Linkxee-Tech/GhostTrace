import React, { useState, useEffect } from "react";
import "./GhostTrace.css";

// Components
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { Dashboard } from "./components/Dashboard";
import { ScanHistory } from "./components/ScanHistory";
import { FileScanner } from "./components/FileScanner";
import { URLScanner } from "./components/URLScanner";
import { LogAnalyzer } from "./components/LogAnalyzer";
import { IOCExtractor } from "./components/IOCExtractor";
import { AttackTimeline } from "./components/AttackTimeline";
import { ThreatIntel } from "./components/ThreatIntel";
import { Reports } from "./components/Reports";
import { Settings } from "./components/Settings";
import { About } from "./components/About";
import { Privacy } from "./components/Privacy";
import { Terms } from "./components/Terms";

// Utils & Constants
import { HISTORY, API_STORAGE_KEY } from "./components/SOCConstants";
import { apiJson, mapHistoryItem, normalizeLevel, reportClientError } from "./components/SOCUtils";

export default function GhostTrace() {
  const [view, setView] = useState("dashboard");
  const [historyItems, setHistoryItems] = useState(HISTORY);
  const [reportsData, setReportsData] = useState(null);
  const [pendingScan, setPendingScan] = useState(null);
  const [backendStatus, setBackendStatus] = useState({
    connected: false,
    yara: false,
    authState: "unknown",
    statusText: "Initializing backend status",
    providers: { virustotal: false, abuseipdb: false, phishtank: false, urlscan: false, openai: false },
    provider_status: { virustotal: false, abuseipdb: false, phishtank: false, urlscan: false, openai: false },
    watchlistCount: 0,
    alerts: [],
  });

  const triggerScan = (type, value) => {
    setPendingScan({ type, value });
    const t = String(type).toLowerCase();
    if (t === "url" || t === "ip" || t === "domain") setView("url-scan");
    else if (t === "file" || t === "hash" || t === "md5" || t === "sha256") setView("file-scan");
    else if (t === "log") setView("log-scan");
  };

  const refreshHistoryAndReports = async () => {
    const [files, urls, logs, reports] = await Promise.allSettled([
      apiJson("/api/history/files?limit=200"),
      apiJson("/api/history/urls?limit=200"),
      apiJson("/api/history/logs?limit=200"),
      apiJson("/api/reports?limit=200"),
    ]);

    const filesVal = files.status === "fulfilled" ? files.value : null;
    const urlsVal = urls.status === "fulfilled" ? urls.value : null;
    const logsVal = logs.status === "fulfilled" ? logs.value : null;
    const reportsVal = reports.status === "fulfilled" ? reports.value : null;

    const fileItems = (filesVal?.items || []).map((d) => mapHistoryItem(d, "file"));
    const urlItems = (urlsVal?.items || []).map((d) => mapHistoryItem(d, "url"));
    const logItems = (logsVal?.items || []).map((d) => mapHistoryItem(d, "log"));
    const merged = [...fileItems, ...urlItems, ...logItems].sort((a, b) => b.ts - a.ts);
    if (merged.length) setHistoryItems(merged);
    const reportItems = reportsVal?.items || [];
    if (reportItems.length) setReportsData(reportItems);
  };

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        const [files, urls, logs, reports] = await Promise.allSettled([
          apiJson("/api/history/files?limit=200"),
          apiJson("/api/history/urls?limit=200"),
          apiJson("/api/history/logs?limit=200"),
          apiJson("/api/reports?limit=200"),
        ]);
        if (!mounted) return;
        
        const filesVal = files.status === "fulfilled" ? files.value : null;
        const urlsVal = urls.status === "fulfilled" ? urls.value : null;
        const logsVal = logs.status === "fulfilled" ? logs.value : null;
        const reportsVal = reports.status === "fulfilled" ? reports.value : null;

        const fileItems = (filesVal?.items || []).map((d) => mapHistoryItem(d, "file"));
        const urlItems = (urlsVal?.items || []).map((d) => mapHistoryItem(d, "url"));
        const logItems = (logsVal?.items || []).map((d) => mapHistoryItem(d, "log"));
        const merged = [...fileItems, ...urlItems, ...logItems].sort((a, b) => b.ts - a.ts);
        if (merged.length) setHistoryItems(merged);
        
        const reportItems = reportsVal?.items || [];
        if (reportItems.length) setReportsData(reportItems);
      } catch (e) { reportClientError("Load history/reports failed", e); }
    })();
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    let active = true;
    const loadStatus = async () => {
      try {
        const parseStatus = (res) => (res?.status === "rejected" ? Number(res.reason?.status || 0) : 0);
        const [healthRes, libsRes, monitorRes] = await Promise.allSettled([
          apiJson("/health"),
          apiJson("/api/security-libs-status"),
          apiJson("/api/monitor/status"),
        ]);
        const health = healthRes.status === "fulfilled" ? healthRes.value : null;
        const libs = libsRes.status === "fulfilled" ? libsRes.value : null;
        const monitor = monitorRes.status === "fulfilled" ? monitorRes.value : null;
        const localKeys = (() => {
          try { return JSON.parse(localStorage.getItem(API_STORAGE_KEY) || "{}"); } catch { return {}; }
        })();
        if (!active) return;
        const libsCode = parseStatus(libsRes);
        const monitorCode = parseStatus(monitorRes);
        const healthCode = parseStatus(healthRes);
        const authState = libsCode === 401 || monitorCode === 401
          ? "missing_api_key"
          : libsCode === 403 || monitorCode === 403
            ? "invalid_api_key"
            : libsCode === 500 || monitorCode === 500
              ? "server_misconfigured"
              : "ok";
        const providerStatus = {
          virustotal: Boolean(libs?.provider_status?.virustotal || localKeys?.virustotal),
          abuseipdb: Boolean(libs?.provider_status?.abuseipdb || localKeys?.abuseipdb),
          phishtank: Boolean(libs?.provider_status?.phishtank || localKeys?.phishtank),
          urlscan: Boolean(libs?.provider_status?.urlscan || localKeys?.urlscan),
          openai: Boolean(libs?.provider_status?.openai || localKeys?.openai),
        };
        setBackendStatus({
          connected: Boolean(health?.status === "ok"),
          yara: libs?.yara || { available: false },
          authState,
          statusText: !health
            ? (healthCode === 500 ? "Backend misconfigured" : "Backend down")
            : authState === "missing_api_key"
              ? "Missing API key"
              : authState === "invalid_api_key"
                ? "Invalid API key"
                : authState === "server_misconfigured"
                  ? "Backend misconfigured"
                : "Connected",
          providers: providerStatus,
          provider_status: providerStatus,
          watchlistCount: Array.isArray(monitor?.watchlist) ? monitor.watchlist.length : 0,
          alerts: monitor?.alerts || [],
        });
      } catch (e) {
        reportClientError("Load backend status failed", e);
        if (!active) return;
        setBackendStatus((prev) => ({ ...prev, connected: false, authState: "backend_down", statusText: "Backend down" }));
      }
    };
    loadStatus();
    const id = setInterval(loadStatus, 30000);
    return () => { active = false; clearInterval(id); };
  }, []);

  return (
    <div className="gt">
      <Sidebar view={view} setView={setView} backendStatus={backendStatus} />
      <div className="gt-main">
        <Topbar view={view} backendStatus={backendStatus} historyItems={historyItems} />
        <div className="gt-scroll">
          {view === "dashboard" && <Dashboard setView={setView} historyItems={historyItems} reportsData={reportsData} backendStatus={backendStatus} />}
          {view === "history"   && <ScanHistory setView={setView} historyItems={historyItems} />}
          {view === "file-scan" && <FileScanner pendingScan={pendingScan} setPendingScan={setPendingScan} onScanTrigger={triggerScan} onScanComplete={refreshHistoryAndReports} />}
          {view === "url-scan"  && <URLScanner pendingScan={pendingScan} setPendingScan={setPendingScan} onScanTrigger={triggerScan} onScanComplete={refreshHistoryAndReports} />}
          {view === "log-scan"  && <LogAnalyzer pendingScan={pendingScan} setPendingScan={setPendingScan} onScanTrigger={triggerScan} onScanComplete={refreshHistoryAndReports} />}
          {view === "ioc"       && <IOCExtractor onScanTrigger={triggerScan} />}
          {view === "timeline"  && <AttackTimeline historyItems={historyItems} backendStatus={backendStatus} />}
          {view === "intel"     && <ThreatIntel backendStatus={backendStatus} historyItems={historyItems} onScanTrigger={triggerScan} />}
          {view === "reports"   && <Reports reportsData={reportsData} setView={setView} />}
          {view === "settings"  && <Settings backendStatus={backendStatus} />}
          {view === "about"     && <About />}
          {view === "privacy"   && <Privacy />}
          {view === "terms"     && <Terms />}
        </div>
      </div>
    </div>
  );
}
