import React, { useState, useEffect } from "react";
import { Badge, Pbar } from "./SOCLibrary";
import { HISTORY } from "./SOCConstants";
import { normalizeLevel } from "./SOCUtils";

// Animated counter hook
function useCountUp(target, duration = 900) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!target) return;
    let start = 0;
    const step = target / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= target) { setVal(target); clearInterval(timer); }
      else setVal(Math.floor(start));
    }, 16);
    return () => clearInterval(timer);
  }, [target]);
  return val;
}

// Skeleton shimmer row
function SkeletonRow() {
  return (
    <div className="act-item" style={{ gap: 12 }}>
      <div style={{ width: 34, height: 34, borderRadius: 8, background: "rgba(255,255,255,.05)" }} className="loading-pulse" />
      <div style={{ flex: 1 }}>
        <div style={{ height: 11, borderRadius: 4, background: "rgba(255,255,255,.05)", marginBottom: 6, width: "60%" }} className="loading-pulse" />
        <div style={{ height: 9, borderRadius: 4, background: "rgba(255,255,255,.04)", width: "40%" }} className="loading-pulse" />
      </div>
      <div style={{ width: 48, height: 16, borderRadius: 10, background: "rgba(255,255,255,.04)" }} className="loading-pulse" />
    </div>
  );
}

// Animated threat ring SVG
function ThreatRing({ val, max = 100, level = "low", label = "" }) {
  const r = 38;
  const circ = 2 * Math.PI * r;
  const pct = Math.min(val / max, 1);
  const color = level === "critical" ? "var(--red)" : level === "high" ? "var(--amber)" : level === "medium" ? "var(--blue)" : "var(--green)";
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
      <svg width={96} height={96} viewBox="0 0 96 96" style={{ transform: "rotate(-90deg)" }}>
        <circle cx={48} cy={48} r={r} fill="none" stroke="rgba(255,255,255,.06)" strokeWidth={6} />
        <circle
          cx={48} cy={48} r={r} fill="none" stroke={color} strokeWidth={6}
          strokeDasharray={circ} strokeDashoffset={circ * (1 - pct)}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 1.2s ease", filter: `drop-shadow(0 0 4px ${color})` }}
        />
      </svg>
      <div style={{ marginTop: -8, textAlign: "center" }}>
        <div style={{ fontFamily: "var(--mono)", fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>{val}</div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--t3)", marginTop: 2 }}>{label}</div>
      </div>
    </div>
  );
}

export function Dashboard({ setView, historyItems = HISTORY, reportsData = null, backendStatus = {} }) {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 600);
    return () => clearTimeout(t);
  }, [historyItems]);

  const lvlBg = { critical: "rgba(255,45,85,.1)", high: "rgba(255,170,0,.1)", medium: "rgba(59,130,246,.1)", low: "rgba(0,255,136,.08)", clean: "rgba(0,255,136,.08)" };
  const typeIcon = { file: "📁", url: "🌐", log: "📋", ioc: "🔗" };
  const normalizedHistory = historyItems.map((s) => ({ ...s, level: normalizeLevel(s.level) }));
  const totalScans = historyItems.length;
  const threatCount = normalizedHistory.filter((s) => ["critical", "high", "medium"].includes(s.level)).length;
  const iocCount = historyItems.reduce((n, s) => n + Number(s.iocs || 0), 0);
  const reportCount = Array.isArray(reportsData) ? reportsData.length : 0;
  const criticalCount = normalizedHistory.filter((s) => s.level === "critical").length;
  const recent = historyItems.slice(0, 6);

  const byLevel = {
    critical: normalizedHistory.filter((s) => s.level === "critical").length,
    high: normalizedHistory.filter((s) => s.level === "high").length,
    medium: normalizedHistory.filter((s) => s.level === "medium").length,
    lowClean: normalizedHistory.filter((s) => ["low", "clean"].includes(s.level)).length,
  };
  const pct = (v) => totalScans ? Math.round((Number(v || 0) / totalScans) * 100) : 0;

  const threatRows = [
    { l: "Critical", n: byLevel.critical, c: "var(--red)", p: pct(byLevel.critical), pb: "red" },
    { l: "High", n: byLevel.high, c: "var(--amber)", p: pct(byLevel.high), pb: "amber" },
    { l: "Medium", n: byLevel.medium, c: "var(--blue)", p: pct(byLevel.medium), pb: "blue" },
    { l: "Low / Clean", n: byLevel.lowClean, c: "var(--green)", p: pct(byLevel.lowClean), pb: "green" },
  ];

  const [simFeed, setSimFeed] = useState([]);

  useEffect(() => {
    const liveFeed = (backendStatus?.alerts || []).slice(0, 6).map((a) => [
      a?.url || "monitor-item", "Domain", a?.message || "Elevated risk from monitor check",
      "Monitor", Math.min(99, Number(a?.risk_score || 50)), normalizeLevel(a?.threat_level || "medium"),
    ]);
    const historyFeed = recent.map((s) => [
      s.name || "scan-item", String(s.type || "scan").toUpperCase(),
      `${String(s.level || "unknown").toUpperCase()} risk scan`, "GhostTrace",
      Math.min(99, Number(s.risk || 0)), normalizeLevel(s.level || "medium"),
    ]);

    const initial = liveFeed.length ? liveFeed : (historyFeed.length ? historyFeed : [
      ["185.220.101.47", "IP", "SSH brute-force login storm detected", "IDS", 94, "critical"],
      ["secure-paypa1.com", "DOMAIN", "Brand typosquatting phishing host identified", "PhishTank", 88, "critical"],
      ["invoice_update_Q4.exe", "HASH", "Trojan.Win32.Emotet rule matched via YARA", "File Scanner", 97, "critical"],
      ["10.0.0.5", "IP", "Privilege escalation: sudo exploit attempted", "Host Monitor", 72, "high"],
      ["bad-actor-c2.ru", "DOMAIN", "Periodic HTTP C2 beaconing pattern observed", "Traffic Analyzer", 83, "high"]
    ]);
    setSimFeed(initial);

    const pool = [
      ["185.220.101.47", "IP", "SSH brute-force login storm detected", "IDS", 94, "critical"],
      ["secure-paypa1.com", "DOMAIN", "Brand typosquatting phishing host identified", "PhishTank", 88, "critical"],
      ["invoice_update_Q4.exe", "HASH", "Trojan.Win32.Emotet rule matched via YARA", "File Scanner", 97, "critical"],
      ["10.0.0.5", "IP", "Privilege escalation: sudo exploit attempted", "Host Monitor", 72, "high"],
      ["bad-actor-c2.ru", "DOMAIN", "Periodic HTTP C2 beaconing pattern observed", "Traffic Analyzer", 83, "high"],
      ["svchost32.exe", "FILE", "Persistence autorun key registered in ProgramData", "Security Registry", 89, "critical"],
      ["192.168.1.105", "IP", "Internal network scanning sweep detected", "Intrusion Detection", 65, "medium"],
      ["update_patch.js", "FILE", "Obfuscated shellcode downloader segment found", "Code Guard", 78, "high"],
      ["checkout-secure.net", "DOMAIN", "Newly registered domain acting as credential collector", "Reputation Checker", 91, "critical"],
      ["cmd.exe", "PROCESS", "Suspicious Base64 encoded PowerShell string execution", "Process Monitor", 85, "high"],
    ];

    const interval = setInterval(() => {
      setSimFeed(prev => {
        const unused = pool.filter(p => !prev.some(pr => pr[0] === p[0]));
        const nextItem = unused.length ? unused[Math.floor(Math.random() * unused.length)] : pool[Math.floor(Math.random() * pool.length)];
        return [nextItem, ...prev.slice(0, 5)];
      });
    }, 10000);

    return () => clearInterval(interval);
  }, [backendStatus?.alerts, historyItems]);

  const feedRows = simFeed;

  const animTotal = useCountUp(totalScans);
  const animThreats = useCountUp(threatCount);
  const animIocs = useCountUp(iocCount);
  const animReports = useCountUp(reportCount);

  const [showTour, setShowTour] = useState(false);

  return (
    <div className="view">

      {/* ── Playbook Tour Trigger Button / Expanded Info Banner ── */}
      {!showTour ? (
        <div style={{
          background: "rgba(139,92,246,.05)",
          border: "1px dashed rgba(139,92,246,.25)",
          borderRadius: 12, padding: "14px 20px",
          marginBottom: 20, display: "flex", justifyContent: "space-between", alignItems: "center",
          flexWrap: "wrap", gap: 12
        }}>
          <div className="fac gap10">
            <span style={{ fontSize: 16 }}>🎓</span>
            <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--t2)" }}>
              First-time security analyst? Try our <strong>Interactive Guided Incident Playbook Walkthrough</strong>.
            </div>
          </div>
          <button className="btn btn-primary btn-sm" style={{ background: "var(--purple)", borderColor: "var(--purple)", color: "#fff" }} onClick={() => setShowTour(true)}>
            🚀 Expand Tour Info
          </button>
        </div>
      ) : (
        <div style={{
          background: "linear-gradient(135deg, rgba(0,212,255,.07) 0%, rgba(139,92,246,.06) 50%, rgba(0,255,136,.05) 100%)",
          border: "1px solid rgba(0,212,255,.2)", borderRadius: 12, padding: "24px 28px",
          marginBottom: 20, position: "relative", overflow: "hidden",
          boxShadow: "0 4px 20px rgba(0,0,0,.15)",
          animation: "fadeDown .3s ease"
        }}>
          <div style={{ position: "absolute", inset: 0, backgroundImage: "radial-gradient(circle at 90% 10%, rgba(0,255,136,.06) 0%, transparent 60%)", pointerEvents: "none" }} />
          <div className="scan-beam" />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 20, position: "relative" }}>
            <div style={{ flex: 1 }}>
              <div className="fac gap8 mb6" style={{ flexWrap: "wrap" }}>
                <span style={{ fontSize: 18 }}>🎓</span>
                <div style={{ fontSize: 18, fontWeight: 900, background: "linear-gradient(130deg, var(--cyan), var(--green))", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                  Interactive Incident Response Playbook
                </div>
                <Badge level="purple">Recommended for New Users</Badge>
              </div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--t2)", marginBottom: 16, lineHeight: 1.7, maxWidth: 800 }}>
                Trace a live cyber threat from initial ingress to final exfiltration. In this interactive simulation, you will triage an active firewall alert, perform PE binary static forensics on an Emotet Trojan dropper, resolve passive threat intelligence markers, parse intrusion logs, reconstruct the attack chain mapped to MITRE ATT&CK®, and download a formal Incident Report.
              </div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <button className="btn btn-primary btn-sm" onClick={() => { setShowTour(false); setView("walkthrough"); }}>🚀 Launch Playbook Simulation</button>
                <button className="btn btn-sec btn-sm" onClick={() => setView("file-scan")}>🔍 Manual File Scanner</button>
                <button className="btn btn-ghost btn-sm" onClick={() => setShowTour(false)}>Collapse Info</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Stat Grid ── */}
      <div className="stat-grid">
        <div className="stat c-cyan">
          <div className="stat-val" style={{ color: "var(--cyan)" }}>{animTotal}</div>
          <div className="stat-lbl">Total Scans</div>
          <div className="stat-sub">Loaded from backend history</div>
        </div>
        <div className="stat c-red">
          <div className="stat-val" style={{ color: "var(--red)" }}>{animThreats}</div>
          <div className="stat-lbl">Threats Detected</div>
          <div className="stat-sub">{totalScans ? `${Math.round((threatCount / totalScans) * 100)}% detection rate` : "No scans yet"}</div>
        </div>
        <div className="stat c-amber">
          <div className="stat-val" style={{ color: "var(--amber)" }}>{animIocs}</div>
          <div className="stat-lbl">IOCs Extracted</div>
          <div className="stat-sub">IPs, domains, hashes</div>
        </div>
        <div className="stat c-green">
          <div className="stat-val" style={{ color: "var(--green)" }}>{animReports}</div>
          <div className="stat-lbl">Reports Generated</div>
          <div className="stat-sub">PDF forensic reports</div>
        </div>
      </div>

      {/* ── Main Row ── */}
      <div className="g2 mb20">
        {/* Recent Scans */}
        <div className="card">
          <div className="card-hd">
            <span className="card-title">⏱ Recent Scans</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setView("history")}>All scans →</button>
          </div>
          <div className="card-body">
            {loading
              ? [1, 2, 3].map((k) => <SkeletonRow key={k} />)
              : recent.length === 0
                ? (
                  <div className="empty-state">
                    <div className="empty-icon">🔍</div>
                    <div className="empty-title">No scans yet</div>
                    <div className="empty-sub">Run your first file, URL, or log analysis<br />to see activity here.</div>
                  </div>
                )
                : recent.map((s, i) => (
                  <div key={i} className="act-item">
                    <div className="act-icon-box" style={{ background: lvlBg[s.level] || lvlBg.low }}>{typeIcon[s.type]}</div>
                    <div className="f1" style={{ minWidth: 0 }}>
                      <div className="act-name">{s.name}</div>
                      <div className="act-meta">{s.type.toUpperCase()} · {s.date} · {s.findings} findings</div>
                    </div>
                    <Badge level={s.level} />
                  </div>
                ))
            }
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          {/* Threat Breakdown with ring */}
          <div className="card">
            <div className="card-hd"><span className="card-title">📊 Threat Breakdown</span></div>
            <div className="card-body" style={{ display: "flex", gap: 20, alignItems: "center" }}>
              <ThreatRing
                val={criticalCount}
                max={Math.max(totalScans, 1)}
                level={criticalCount > 0 ? "critical" : "low"}
                label="CRITICAL"
              />
              <div style={{ flex: 1 }}>
                {threatRows.map((r) => (
                  <div key={r.l} className="mb12">
                    <div className="fjsb mb6 mono txt-xs">
                      <span style={{ color: r.c }}>{r.l}</span>
                      <span className="txt-muted">{r.n} scans</span>
                    </div>
                    <Pbar val={r.p} color={r.pb} />
                  </div>
                ))}
              </div>
            </div>
          </div>

           {/* Quick Launch */}
          <div className="card">
            <div className="card-hd"><span className="card-title">⚡ Quick Launch</span></div>
            <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <button className="btn btn-primary w100" onClick={() => setView("walkthrough")}>🎓 Playbook Walkthrough</button>
              <button className="btn btn-sec w100" onClick={() => setView("file-scan")}>🔍 Scan File / Malware</button>
              <button className="btn btn-ghost w100" onClick={() => setView("url-scan")}>🌐 Scan URL / Website</button>
              <button className="btn btn-ghost w100" onClick={() => setView("log-scan")}>📋 Analyze Logs</button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Live Threat Feed ── */}
      <div className="card">
        <div className="card-hd">
          <span className="card-title">🌍 Live Threat Intelligence Feed</span>
          <span className="fac gap6 mono txt-xs txt-muted">
            <span className="live-dot" />
            {backendStatus?.alerts?.length ? "LIVE · Updated from monitor alerts" : "LIVE · Simulated real-time intelligence feed"}
          </span>
        </div>
        <div style={{ padding: 0 }}>
          {feedRows.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">📡</div>
              <div className="empty-title">No threat intelligence yet</div>
              <div className="empty-sub">
                Add URLs to the monitor watchlist or run scans<br />
                to populate the live threat feed.
              </div>
            </div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <th>Indicator</th><th>Type</th><th>Malware / Threat</th>
                  <th>Source</th><th>Confidence</th><th>Status</th>
                </tr>
              </thead>
              <tbody>
                {feedRows.map(([ioc, type, threat, src, conf, level], i) => (
                  <tr key={i} style={{ animation: `fadeUp ${0.1 + i * 0.04}s ease` }}>
                    <td><span className="hash-pill">{ioc}</span></td>
                    <td><Badge level={type === "IP" ? "info" : "purple"}>{type}</Badge></td>
                    <td style={{ color: "var(--t1)" }}>{threat}</td>
                    <td className="txt-muted">{src}</td>
                    <td>
                      <div className="fac gap6">
                        <div style={{ width: 60 }}><Pbar val={conf} color={conf > 85 ? "red" : "amber"} /></div>
                        <span className="mono txt-xs txt-muted" style={{ minWidth: 28 }}>{conf}%</span>
                      </div>
                    </td>
                    <td><Badge level={level}>{level.toUpperCase()}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* ── Platform Capabilities Strip ── */}
      <div className="feat-grid" style={{ marginTop: 14 }}>
        {[
          { icon: "📁", name: "File Forensics", desc: "PE analysis, entropy, YARA, packed detection", view: "file-scan" },
          { icon: "🌐", name: "URL Intelligence", desc: "Phishing, DNS, SSL, reputation scoring", view: "url-scan" },
          { icon: "📋", name: "Log Analysis", desc: "Brute-force, lateral movement, C2 detection", view: "log-scan" },
          { icon: "🔗", name: "IOC Extraction", desc: "IPs, domains, hashes, CVEs, commands", view: "ioc" },
          { icon: "🕵", name: "Attack Timeline", desc: "Incident reconstruction from scan history", view: "timeline" },
          { icon: "📑", name: "Intelligence Reports", desc: "PDF forensic reports with MITRE mapping", view: "reports" },
        ].map((cap) => (
          <div key={cap.view} className="feat-card" onClick={() => setView(cap.view)} style={{ cursor: "pointer" }}>
            <div className="feat-icon">{cap.icon}</div>
            <div className="feat-name">{cap.name}</div>
            <div className="feat-desc">{cap.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
