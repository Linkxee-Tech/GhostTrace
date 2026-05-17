import React, { useState } from "react";
import { Badge } from "./SOCLibrary";
import { apiBlob, downloadBlob, downloadJson, openBlobInNewTab, reportClientError } from "./SOCUtils";

const TYPE_ICON = { file: "📁", url: "🌐", log: "📋" };
const TYPE_BG   = {
  file:    "rgba(255,45,85,.1)",
  url:     "rgba(59,130,246,.1)",
  log:     "rgba(255,170,0,.1)",
  unknown: "rgba(255,255,255,.04)",
};

function normalizeReportItem(r, i) {
  // Accepts both legacy static shape AND real DB document shape
  if (r.name && r.meta) return { ...r, sourceId: r.id || null }; // already in display shape
  const type = String(r.report_type || r.type || "file").toLowerCase();
  const severity = String(r.severity || r.level || "unknown").toLowerCase();
  const target = r.filename || r.url || r.target || `Scan #${i + 1}`;
  const date = r.created_at ? new Date(r.created_at).toLocaleString() : "—";
  const summarySnippet = (r.result_summary || "").slice(0, 80);
  return {
    ic: TYPE_ICON[type] || "📄",
    bg: TYPE_BG[type] || TYPE_BG.unknown,
    name: `${target} — ${type === "file" ? "Malware Analysis" : type === "url" ? "Web Investigation" : "Log Forensics"}`,
    meta: `${severity.toUpperCase()} · ${type.toUpperCase()} · ${date}`,
    sz: summarySnippet || "GhostTrace report",
    level: severity,
    sourceType: type,
    sourceTarget: r.url || r.target || r.filename || "",
    sourceId: r.id || null,
    id: r.id || String(i),
  };
}

export function Reports({ reportsData = null, setView }) {
  const DEMO_REPORTS = [
    { ic:"📁", bg:"rgba(255,45,85,.1)",  name:"invoice_update_Q4.exe — Malware Analysis",   meta:"CRITICAL · PE32 Emotet Trojan · 2024-11-30 14:22",    sz:"1.2 MB",  level:"critical", sourceType:"file" },
    { ic:"🌐", bg:"rgba(59,130,246,.1)", name:"secure-paypa1.com — Phishing Investigation",  meta:"CRITICAL · PayPal Credential Harvest · 2024-11-30 14:08", sz:"890 KB",  level:"critical", sourceType:"url" },
    { ic:"📋", bg:"rgba(255,170,0,.1)",  name:"access_logs_nov.txt — Log Forensics",         meta:"HIGH · C2 + Lateral Movement · 2024-11-30 13:10",      sz:"2.1 MB",  level:"high",     sourceType:"log" },
    { ic:"📁", bg:"rgba(255,170,0,.1)",  name:"suspicious_update.js — Script Analysis",      meta:"HIGH · Obfuscated Code · 2024-11-30 11:30",            sz:"540 KB",  level:"high",     sourceType:"file" },
    { ic:"📁", bg:"rgba(0,255,136,.08)", name:"company_logo.png — File Verification",        meta:"CLEAN · No threats detected · 2024-11-30 12:44",       sz:"120 KB",  level:"clean",    sourceType:"file" },
  ];

  const rawReports = Array.isArray(reportsData) && reportsData.length > 0 ? reportsData : DEMO_REPORTS;
  const allReports = rawReports.map((r, i) => normalizeReportItem(r, i));

  const [q, setQ] = useState("");
  const [filterLevel, setFilterLevel] = useState("all");
  const [downloading, setDownloading] = useState(null);
  const [pdfError, setPdfError] = useState("");

  const openInlinePreview = (r) => {
    const level = String(r.level || "unknown").toUpperCase();
    const type = String(r.sourceType || "report").toUpperCase();
    const name = String(r.name || "GhostTrace Report");
    const meta = String(r.meta || "Generated report metadata unavailable.");
    const size = String(r.sz || "N/A");
    const safe = (v) => String(v)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>GhostTrace Report Preview</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; background:#0b0f14; color:#d9e2ec; margin:0; padding:24px; }
    .card { max-width:880px; margin:0 auto; background:#111821; border:1px solid #223142; border-radius:12px; padding:20px; }
    .h { color:#37e8ff; font-weight:700; font-size:20px; margin-bottom:8px; }
    .sub { color:#8ca1b6; margin-bottom:18px; }
    .row { margin:8px 0; }
    .k { color:#8ca1b6; display:inline-block; min-width:90px; }
    .v { color:#e8edf5; font-weight:600; }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; background:#19304a; color:#7ed5ff; font-size:12px; }
    .wm { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; pointer-events:none; opacity:.08; font-size:72px; font-weight:800; color:#00ff88; }
  </style>
</head>
<body>
  <div class="wm">GHOSTTRACE</div>
  <div class="card">
    <div class="h">Report Preview</div>
    <div class="sub">Quick report preview: this view presents the record summary (name, type, severity, metadata, and size) for rapid review.</div>
    <div class="row"><span class="k">Name:</span> <span class="v">${safe(name)}</span></div>
    <div class="row"><span class="k">Type:</span> <span class="badge">${safe(type)}</span></div>
    <div class="row"><span class="k">Severity:</span> <span class="badge">${safe(level)}</span></div>
    <div class="row"><span class="k">Metadata:</span> <span class="v">${safe(meta)}</span></div>
    <div class="row"><span class="k">Size/Summary:</span> <span class="v">${safe(size)}</span></div>
  </div>
</body>
</html>`;
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  };

  const filtered = allReports.filter((r) => {
    const txt = `${r.name} ${r.meta}`.toLowerCase();
    const lvl = String(r.level || "").toLowerCase();
    const matchQ = !q || txt.includes(q.toLowerCase());
    const matchLvl = filterLevel === "all" || lvl === filterLevel;
    return matchQ && matchLvl;
  });

  const stats = allReports.reduce((acc, r) => {
    acc.total++;
    if (["critical","high","medium"].includes(String(r.level||"").toLowerCase())) acc.threat++;
    return acc;
  }, { total: 0, threat: 0 });

  const handlePdfDownload = async (r, i) => {
    setDownloading(i);
    setPdfError("");
    try {
      if (r.sourceId) {
        const blob = await apiBlob(`/api/reports/${encodeURIComponent(r.sourceId)}/pdf`);
        downloadBlob(blob, `ghosttrace_report_${r.sourceId}.pdf`);
        return;
      }
      const blob = await apiBlob("/api/reports/preview-pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: r.name,
          report_type: r.sourceType,
          severity: r.level,
          target: r.sourceTarget || r.name,
          result_summary: r.sz,
          created_at: r.meta,
        }),
      });
      downloadBlob(blob, `ghosttrace_report_${Date.now()}.pdf`);
    } catch (e) {
      reportClientError("PDF download failed", e);
      setPdfError("PDF generation failed from backend. A JSON export was downloaded as fallback.");
      downloadJson(r, `ghosttrace_report_${i + 1}.json`);
    } finally {
      setDownloading(null);
    }
  };

  const handleView = async (r) => {
    const t = String(r.sourceType || "").toLowerCase();
    try {
      if (r.sourceId) {
        const blob = await apiBlob(`/api/reports/${encodeURIComponent(r.sourceId)}/pdf`);
        openBlobInNewTab(blob);
        return;
      }
      if (t === "url" && r.sourceTarget) {
        const blob = await apiBlob("/api/generate-url-report", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: r.sourceTarget }),
        });
        openBlobInNewTab(blob);
        return;
      }
      openInlinePreview(r);
    } catch (e) {
      reportClientError("Report view failed", e);
      openInlinePreview(r);
    }
  };

  const LEVELS = ["all","critical","high","medium","low","clean"];

  return (
    <div className="view">
      <div className="fjsb mb20">
        <div>
          <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>📑 Investigation Reports</div>
          <div className="txt-sec txt-sm">Downloadable PDF forensic reports for all completed investigations</div>
        </div>
        <div className="fac gap8">
          <button className="btn btn-ghost btn-sm" onClick={() => downloadJson(allReports, "ghosttrace_reports_archive.json")}>⬇ Export All</button>
          <button className="btn btn-primary" onClick={() => setView("file-scan")}>+ New Scan</button>
        </div>
      </div>
      {pdfError && <div className="warn-box mb12">{pdfError}</div>}

      {/* Stats */}
      <div className="g3 mb16">
        <div className="stat c-green"><div className="stat-val" style={{color:"var(--green)"}}>{stats.total}</div><div className="stat-lbl">Reports Generated</div><div className="stat-sub">{reportsData?.length > 0 ? "From backend history" : "Demo reports shown"}</div></div>
        <div className="stat c-red"><div className="stat-val" style={{color:"var(--red)"}}>{stats.threat}</div><div className="stat-lbl">Threat Investigations</div><div className="stat-sub">Critical, High & Medium</div></div>
        <div className="stat c-cyan"><div className="stat-val" style={{color:"var(--cyan)"}}>{Math.round((stats.threat/(stats.total||1))*100)}%</div><div className="stat-lbl">Detection Rate</div><div className="stat-sub">Across all report types</div></div>
      </div>

      {/* Report archive */}
      <div className="card mb16">
        <div className="card-hd">
          <span className="card-title">📋 Report Archive</span>
          <div className="fac gap8">
            {/* Severity filter */}
            <div className="fac gap4">
              {LEVELS.map(l => (
                <button key={l} className={`btn btn-sm ${filterLevel === l ? "btn-primary" : "btn-ghost"}`} style={{ padding:"3px 9px", fontSize:10 }} onClick={() => setFilterLevel(l)}>
                  {l === "all" ? "All" : l.charAt(0).toUpperCase() + l.slice(1)}
                </button>
              ))}
            </div>
            <div className="search-bar" style={{ width:200, height:32 }}>
              <span className="txt-muted" style={{fontSize:13}}>🔍</span>
              <input placeholder="Search reports…" value={q} onChange={e => setQ(e.target.value)} />
            </div>
          </div>
        </div>
        <div className="card-body">
          {filtered.map((r, i) => (
            <div key={i} className="rep-card">
              <div className="rep-icon" style={{ background: r.bg }}>{r.ic}</div>
              <div className="rep-card-inner">
                <div className="rep-name">{r.name}</div>
                <div className="rep-meta">{r.sz}</div>
                <div className="rep-badge-row">
                  <Badge level={r.level}>{r.level?.toUpperCase()}</Badge>
                  <span className="mono txt-xs txt-muted">{r.meta}</span>
                </div>
              </div>
              <div className="fac gap6">
                <button className="btn btn-ghost btn-sm" onClick={() => handleView(r)}>↗ View</button>
                <button
                  className="btn btn-sec btn-sm"
                  disabled={downloading === i}
                  onClick={() => handlePdfDownload(r, i)}
                >
                  {downloading === i ? "…" : "⬇ PDF"}
                </button>
              </div>
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">📄</div>
              <div className="empty-title">No reports match your filter</div>
              <div className="empty-sub">Try clearing the search or switching the severity filter.</div>
            </div>
          )}
        </div>
      </div>

      {/* Report template preview */}
      <div className="card">
        <div className="card-hd"><span className="card-title">📄 PDF Report Template Preview</span></div>
        <div className="card-body">
          <div className="code-block">
<span style={{color:"var(--cyan)"}}>══════════════════════════════════════════════════
</span><span style={{color:"var(--green)",fontWeight:700}}>  GHOSTTRACE · Forensic Investigation Report
</span><span style={{color:"var(--t3)"}}>  Generated: {new Date().toLocaleString()}  ·  CONFIDENTIAL
</span><span style={{color:"var(--cyan)"}}>══════════════════════════════════════════════════
</span><span style={{color:"var(--amber)",fontWeight:700}}>
  [EXECUTIVE SUMMARY]
</span><span style={{color:"var(--t1)"}}>  AI-powered investigation with evidence-based threat analysis.
</span><span style={{color:"var(--amber)",fontWeight:700}}>
  [RISK ASSESSMENT]
</span><span style={{color:"var(--red)"}}>  Score: XX/100  ·  SEVERITY  ·  Confidence: XX%
</span><span style={{color:"var(--amber)",fontWeight:700}}>
  [IOC SUMMARY]
</span><span style={{color:"var(--t2)"}}>  Domains · IPs · Hashes · Scripts · Commands
</span><span style={{color:"var(--amber)",fontWeight:700}}>
  [MITRE ATT&CK TECHNIQUES]
</span><span style={{color:"var(--t2)"}}>  T1566 · T1059 · T1071 · T1027 · T1055
</span><span style={{color:"var(--amber)",fontWeight:700}}>
  [REMEDIATION STEPS]
</span><span style={{color:"var(--t2)"}}>  1. Isolate affected asset immediately
  2. Block extracted indicators at perimeter
  3. Preserve forensic evidence before remediation
</span>
          </div>
        </div>
      </div>
    </div>
  );
}
