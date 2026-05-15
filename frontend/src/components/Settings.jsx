import React, { useState, useEffect, useCallback } from "react";
import { Badge, Toggle } from "./SOCLibrary";
import { SETTINGS_STORAGE_KEY, API_STORAGE_KEY } from "./SOCConstants";
import { apiJson, setRuntimeApiKey, reportClientError, normalizeLevel } from "./SOCUtils";

export function Settings({ backendStatus }) {
  const [t, setT] = useState({
    deep:true, yara:true, ai:true, ioc_export:false, pdf_auto:true,
    vt:true, phishtank:true, abuseipdb:true, urlscan:true, threatfox:false,
  });
  const [keys, setKeys] = useState({
    ghosttrace: "",
    virustotal: "",
    abuseipdb: "",
    openai: "",
    urlscan: "",
    phishtank: "",
  });
  const [serverMasked, setServerMasked] = useState({});
  const [watchUrl, setWatchUrl] = useState("");
  const [watchlist, setWatchlist] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [monitorMsg, setMonitorMsg] = useState("");
  const [monitorBusy, setMonitorBusy] = useState(false);
  const tog = k => setT(p => ({ ...p, [k]: !p[k] }));
  const setKey = (k, v) => setKeys((prev) => ({ ...prev, [k]: v }));

  useEffect(() => {
    try {
      const storedToggles = localStorage.getItem(SETTINGS_STORAGE_KEY);
      if (storedToggles) setT((prev) => ({ ...prev, ...JSON.parse(storedToggles) }));
      const storedKeys = localStorage.getItem(API_STORAGE_KEY);
      if (storedKeys) {
        const parsed = JSON.parse(storedKeys);
        setKeys((prev) => ({ ...prev, ...parsed }));
        if (parsed?.ghosttrace) setRuntimeApiKey(parsed.ghosttrace);
      }
    } catch (e) { reportClientError("Load local settings failed", e); }
  }, []);

  const loadMonitor = useCallback(async () => {
    try {
      const data = await apiJson("/api/monitor/status");
      setWatchlist(Array.isArray(data?.watchlist) ? data.watchlist : []);
      setAlerts(Array.isArray(data?.alerts) ? data.alerts : []);
    } catch (e) { reportClientError("Load monitor status failed", e); }
  }, []);

  useEffect(() => { loadMonitor(); }, [loadMonitor]);

  useEffect(() => {
    (async () => {
      try {
        const data = await apiJson("/api/settings/api-keys");
        setServerMasked(data?.masked || {});
      } catch (e) {
        reportClientError("Load API keys from backend failed", e);
      }
    })();
  }, []);

  useEffect(() => {
    try { localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(t)); } catch (e) { reportClientError("Persist toggles failed", e); }
  }, [t]);

  const saveApiKeys = async () => {
    try { localStorage.setItem(API_STORAGE_KEY, JSON.stringify(keys)); } catch (e) { reportClientError("Persist API keys failed", e); }
    setRuntimeApiKey(keys.ghosttrace);
    try {
      await apiJson("/api/settings/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ghosttrace_api_key: keys.ghosttrace || "",
          virustotal_api_key: keys.virustotal || "",
          abuseipdb_api_key: keys.abuseipdb || "",
          openai_api_key: keys.openai || "",
          urlscan_api_key: keys.urlscan || "",
          phishtank_api_key: keys.phishtank || "",
        }),
      });
    } catch (e) { reportClientError("Save API keys to backend failed", e); }
  };

  const addWatch = async () => {
    const raw = String(watchUrl || "").trim();
    if (!raw) {
      setMonitorMsg("Enter a URL first.");
      return;
    }
    let normalized = raw;
    if (!/^https?:\/\//i.test(normalized)) normalized = `https://${normalized}`;
    try {
      const parsed = new URL(normalized);
      if (!parsed.hostname) throw new Error("Invalid URL");
      normalized = parsed.toString();
    } catch {
      setMonitorMsg("Invalid URL. Use a valid domain or full URL.");
      return;
    }
    setMonitorBusy(true);
    try {
      await apiJson("/api/monitor/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized }),
      });
      setWatchUrl("");
      await loadMonitor();
      setMonitorMsg(`Added to watchlist: ${normalized}`);
    } catch (e) {
      reportClientError("Add monitor URL failed", e);
      setMonitorMsg(`Add failed: ${e?.message || "Request failed"}`);
    } finally { setMonitorBusy(false); }
  };

  const runMonitorCheck = async () => {
    setMonitorBusy(true);
    try {
      await apiJson("/api/monitor/check", { method: "POST" });
      await loadMonitor();
      setMonitorMsg("Monitor check completed.");
    } catch (e) {
      reportClientError("Run monitor check failed", e);
      setMonitorMsg(`Run Check failed: ${e?.message || "Request failed"}`);
    } finally { setMonitorBusy(false); }
  };

  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>⚙ Settings & Configuration</div>
        <div className="txt-sec txt-sm">API keys · Scan engine options · AI model · Security & privacy</div>
      </div>

      <div className="g2">
        <div>
          <div className="card mb14">
            <div className="card-hd"><span className="card-title">🔑 API Keys</span><Badge level={backendStatus?.authState === "ok" ? "clean" : "amber"}>{backendStatus?.authState === "missing_api_key" ? "Missing API Key" : backendStatus?.authState === "invalid_api_key" ? "Invalid API Key" : backendStatus?.connected ? "Backend Connected" : "Backend Unreachable"}</Badge></div>
            <div className="card-body">
              {[["GhostTrace API Key","Required when backend enforces x-api-key","ghosttrace", "ghosttrace_api_key"],
                ["VirusTotal API Key","VT-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX","virustotal", "virustotal_api_key"],
                ["AbuseIPDB API Key","Your AbuseIPDB token here","abuseipdb", "abuseipdb_api_key"],
                ["OpenAI API Key","sk-proj-…","openai", "openai_api_key"],
                ["URLScan.io API Key","Your URLScan key","urlscan", "urlscan_api_key"],
                ["PhishTank App Key","Your PhishTank key","phishtank", "phishtank_api_key"],
              ].map(([lbl, ph, keyName, serverKey]) => (
                <div key={lbl} className="mb12">
                  <label className="inp-label">{lbl}</label>
                  <input className="inp" type="password" placeholder={keys[keyName] ? ph : (serverMasked[serverKey] || ph)} value={keys[keyName] || ""} onChange={e => setKey(keyName, e.target.value)} />
                </div>
              ))}
              <button className="btn btn-primary mt8" onClick={saveApiKeys}>💾 Save API Keys</button>
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">🤖 AI Engine</span></div>
            <div className="card-body">
              <label className="inp-label">Primary AI Model</label>
              <select className="inp sel mb12">
                <option>GPT-4o (Recommended — Best Analysis)</option>
                <option>GPT-4 Turbo</option>
                <option>GPT-3.5 Turbo (Faster / Cheaper)</option>
                <option>Local LLM via Ollama (Air-Gapped)</option>
              </select>
              <label className="inp-label">Local LLM Endpoint (Optional)</label>
              <input className="inp mb12" placeholder="http://localhost:11434 (Ollama default)" />
              <div className="info-box">Local LLM mode processes all data on-premise — recommended for sensitive investigations or air-gapped environments.</div>
            </div>
          </div>
        </div>

        <div>
          <div className="card mb14">
            <div className="card-hd"><span className="card-title">⚡ Scan Engine Options</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["deep",       "Deep Content Scan",       "Fetch and analyze full page HTML, scripts, and resources"],
                ["yara",       "YARA Signature Matching", "Enable local YARA engine with 10,204 curated rules"],
                ["ai",         "AI Threat Explanation",   "Generate explainable AI analysis for every finding"],
                ["ioc_export", "Auto-Export IOCs",        "Download IOC JSON automatically after each scan"],
                ["pdf_auto",   "Auto PDF Generation",     "Create downloadable forensic report after each scan"],
              ].map(([k, title, desc]) => (
                <div key={k} className="ck-row">
                  <div className="f1">
                    <div style={{ fontSize:12.5, fontWeight:600, color:"var(--t1)" }}>{title}</div>
                    <div className="mono txt-xs txt-muted">{desc}</div>
                  </div>
                  <Toggle on={t[k]} onChange={() => tog(k)} />
                </div>
              ))}
            </div>
          </div>

          <div className="card mb14">
            <div className="card-hd"><span className="card-title">📡 Threat Intelligence APIs</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["vt",        "VirusTotal",    "Hash + URL reputation (72 engines)"],
                ["phishtank", "PhishTank",     "Phishing URL real-time verification"],
                ["abuseipdb", "AbuseIPDB",     "IP abuse report lookups"],
                ["urlscan",   "URLScan.io",    "URL behavior + screenshot analysis"],
                ["threatfox", "ThreatFox",     "MalwareBazaar IOC feeds"],
              ].map(([k, name, desc]) => (
                <div key={k} className="ck-row">
                  <div className="f1">
                    <div style={{ fontSize:12.5, fontWeight:600, color:"var(--t1)" }}>{name}</div>
                    <div className="mono txt-xs txt-muted">{desc}</div>
                  </div>
                  <Toggle on={t[k]} onChange={() => tog(k)} />
                </div>
              ))}
            </div>
          </div>

          <div className="card mb14">
            <div className="card-hd"><span className="card-title">👁 Monitor Controls</span></div>
            <div className="card-body">
              <label className="inp-label">Add URL To Watchlist</label>
              <div className="fac gap8 mb12">
                <input className="inp f1" placeholder="https://example.com" value={watchUrl} onChange={(e) => setWatchUrl(e.target.value)} />
                <button className="btn btn-primary" onClick={addWatch} disabled={monitorBusy}>Add</button>
                <button className="btn btn-sec" onClick={runMonitorCheck} disabled={monitorBusy}>Run Check</button>
              </div>
              {monitorMsg && <div className="mono txt-xs txt-muted mb8">{monitorMsg}</div>}
              <div className="mono txt-xs txt-muted mb8">Watchlist: {watchlist.length} items · Alerts: {alerts.length}</div>
              <div className="card" style={{ background:"rgba(255,255,255,.01)", border:"1px solid var(--border)" }}>
                <div className="card-body" style={{ maxHeight:180, overflowY:"auto" }}>
                  {(alerts.slice(0, 10)).map((a, i) => (
                    <div key={i} className="ck-row">
                      <div className="ck-lbl" style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a?.url || "-"}</div>
                      <div className="fac gap6">
                        <span className="mono txt-xs txt-muted">{a?.risk_score ?? "-"}</span>
                        <Badge level={normalizeLevel(a?.threat_level || "medium")}>{String(a?.threat_level || "medium").toUpperCase()}</Badge>
                      </div>
                    </div>
                  ))}
                  {!alerts.length && <div className="txt-xs txt-muted">No alerts yet. Add a URL and run check.</div>}
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">📊 Platform Information</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["Version","GhostTrace v2.0.0"],["Build","2024-12 MVP+"],["Backend","FastAPI 0.104 + Python 3.11"],["Database","MongoDB 7.0"],["YARA Rules","10,204 loaded"],["AI Engine","GPT-4o + Ollama local option"],["Max Upload","50 MB per file"],["Scan Rate Limit","20 scans / hour"],["Data Retention","30 days (configurable)"]].map(([k, v]) => (
                <div key={k} className="ck-row">
                  <div className="ck-lbl">{k}</div>
                  <div className="ck-val txt-muted">{v}</div>
                </div>
              ))}
              <div className="ok-box mt12">✓ System status: {backendStatus?.statusText || (backendStatus?.connected ? "Connected" : "Backend down")}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
