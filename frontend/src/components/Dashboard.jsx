import React from "react";
import { Badge, Pbar } from "./SOCLibrary";
import { HISTORY } from "./SOCConstants";
import { normalizeLevel } from "./SOCUtils";

export function Dashboard({ setView, historyItems = HISTORY, reportsData = null, backendStatus = {} }) {
  const lvlBg = { critical:"rgba(255,45,85,.1)", high:"rgba(255,170,0,.1)", medium:"rgba(59,130,246,.1)", low:"rgba(0,255,136,.08)", clean:"rgba(0,255,136,.08)" };
  const typeIcon = { file:"📁", url:"🌐", log:"📋", ioc:"🔗" };
  const totalScans = historyItems.length;
  const threatCount = historyItems.filter((s) => ["critical", "high", "medium"].includes(String(s.level))).length;
  const iocCount = historyItems.reduce((n, s) => n + Number(s.iocs || 0), 0);
  const reportCount = Array.isArray(reportsData) ? reportsData.length : 0;
  const recent = historyItems.slice(0, 6);
  const byLevel = {
    critical: historyItems.filter((s) => String(s.level) === "critical").length,
    high: historyItems.filter((s) => String(s.level) === "high").length,
    medium: historyItems.filter((s) => String(s.level) === "medium").length,
    lowClean: historyItems.filter((s) => ["low", "clean"].includes(String(s.level))).length,
  };
  const pct = (v) => totalScans ? Math.round((Number(v || 0) / totalScans) * 100) : 0;
  const threatRows = [
    { l:"Critical", n:byLevel.critical, c:"var(--red)", p:pct(byLevel.critical), pb:"red" },
    { l:"High", n:byLevel.high, c:"var(--amber)", p:pct(byLevel.high), pb:"amber" },
    { l:"Medium", n:byLevel.medium, c:"var(--blue)", p:pct(byLevel.medium), pb:"blue" },
    { l:"Low / Clean", n:byLevel.lowClean, c:"var(--green)", p:pct(byLevel.lowClean), pb:"green" },
  ];
  const liveFeed = (backendStatus?.alerts || []).slice(0, 6).map((a) => [
    a?.url || "monitor-item",
    "Domain",
    a?.message || "Elevated risk from monitor check",
    "Monitor",
    Math.min(99, Number(a?.risk_score || 50)),
    normalizeLevel(a?.threat_level || "medium"),
  ]);
  const historyFeed = recent.map((s) => [
    s.name || "scan-item",
    String(s.type || "scan").toUpperCase(),
    `${String(s.level || "unknown").toUpperCase()} risk scan`,
    "GhostTrace",
    Math.min(99, Number(s.risk || 0)),
    normalizeLevel(s.level || "medium"),
  ]);
  const feedRows = liveFeed.length ? liveFeed : historyFeed;

  return (
    <div className="view">
      <div className="stat-grid">
        <div className="stat c-cyan"><div className="stat-val" style={{color:"var(--cyan)"}}>{totalScans}</div><div className="stat-lbl">Total Scans</div><div className="stat-sub">Loaded from backend history</div></div>
        <div className="stat c-red"><div className="stat-val" style={{color:"var(--red)"}}>{threatCount}</div><div className="stat-lbl">Threats Detected</div><div className="stat-sub">{totalScans ? `${Math.round((threatCount / totalScans) * 100)}% detection rate` : "No scans yet"}</div></div>
        <div className="stat c-amber"><div className="stat-val" style={{color:"var(--amber)"}}>{iocCount}</div><div className="stat-lbl">IOCs Extracted</div><div className="stat-sub">IPs, domains, hashes</div></div>
        <div className="stat c-green"><div className="stat-val" style={{color:"var(--green)"}}>{reportCount}</div><div className="stat-lbl">Reports Generated</div><div className="stat-sub">PDF forensic reports</div></div>
      </div>

      <div className="g2 mb20">
        <div className="card">
          <div className="card-hd">
            <span className="card-title">⏱ Recent Scans</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setView("history")}>All scans →</button>
          </div>
          <div className="card-body">
            {recent.map((s, i) => (
              <div key={i} className="act-item">
                <div className="act-icon-box" style={{ background: lvlBg[s.level] || lvlBg.low }}>{typeIcon[s.type]}</div>
                <div className="f1" style={{ minWidth: 0 }}>
                  <div className="act-name">{s.name}</div>
                  <div className="act-meta">{s.type.toUpperCase()} · {s.date} · {s.findings} findings</div>
                </div>
                <Badge level={s.level} />
              </div>
            ))}
          </div>
        </div>

        <div style={{ display:"flex", flexDirection:"column", gap:13 }}>
          <div className="card">
            <div className="card-hd"><span className="card-title">📊 Threat Breakdown</span></div>
            <div className="card-body">
              {threatRows.map(r => (
                <div key={r.l} className="mb12">
                  <div className="fjsb mb6 mono txt-xs"><span style={{color:r.c}}>{r.l}</span><span className="txt-muted">{r.n} scans</span></div>
                  <Pbar val={r.p} color={r.pb} />
                </div>
              ))}
            </div>
          </div>
          <div className="card">
            <div className="card-hd"><span className="card-title">⚡ Quick Launch</span></div>
            <div className="card-body" style={{ display:"flex", flexDirection:"column", gap:8 }}>
              <button className="btn btn-primary w100" onClick={() => setView("file-scan")}>🔍 Scan File / Malware</button>
              <button className="btn btn-sec w100" onClick={() => setView("url-scan")}>🌐 Scan URL / Website</button>
              <button className="btn btn-ghost w100" onClick={() => setView("log-scan")}>📋 Analyze Logs</button>
              <button className="btn btn-ghost w100" onClick={() => setView("ioc")}>🔗 Extract IOCs</button>
              <button className="btn btn-ghost w100" onClick={() => setView("timeline")}>🕵 Attack Timeline</button>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <span className="card-title">🌍 Live Threat Intelligence Feed</span>
          <span className="fac gap6 mono txt-xs txt-muted"><span className="live-dot" />{liveFeed.length ? "LIVE · Updated from monitor alerts" : "LIVE · Derived from latest backend scan history"}</span>
        </div>
        <div style={{ padding: 0 }}>
          <table className="tbl">
            <thead><tr><th>Indicator</th><th>Type</th><th>Malware / Threat</th><th>Source</th><th>Confidence</th><th>Status</th></tr></thead>
            <tbody>
              {feedRows.map(([ioc, type, threat, src, conf, level], i) => (
                <tr key={i}>
                  <td><span className="hash-pill">{ioc}</span></td>
                  <td><Badge level={type === "IP" ? "info" : "purple"}>{type}</Badge></td>
                  <td style={{ color:"var(--t1)" }}>{threat}</td>
                  <td className="txt-muted">{src}</td>
                  <td><div className="fac gap6"><div style={{width:60}}><Pbar val={conf} color={conf > 85 ? "red" : "amber"} /></div><span className="mono txt-xs txt-muted" style={{minWidth:28}}>{conf}%</span></div></td>
                  <td><Badge level={level}>{level.toUpperCase()}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
