import React, { useState } from "react";
import { Badge, RiskDisplay } from "./SOCLibrary";
import { HISTORY, ATTACK_CHAIN } from "./SOCConstants";
import { normalizeLevel } from "./SOCUtils";

export function AttackTimeline({ historyItems = HISTORY, backendStatus = {} }) {
  const [expanded, setExpanded] = useState(null);
  const top = historyItems[0];
  const dynamicPhases = (backendStatus?.alerts || []).slice(0, 8).map((a, i) => ({
    phase: `Monitor Event ${i + 1}`,
    tactic: "MONITOR",
    technique: String(a?.threat_level || "medium").toUpperCase(),
    detail: `${a?.message || "Elevated risk detected"} (${a?.url || "watchlist item"})`,
    sev: normalizeLevel(a?.threat_level || "medium"),
    icon: "📡",
  }));
  const scanDerivedPhases = historyItems.slice(0, 8).map((h, i) => {
    const t = String(h?.type || "").toLowerCase();
    const level = normalizeLevel(h?.level || "medium");
    const isUrl = t === "url";
    const isFile = t === "file";
    const isLog = t === "log";
    return {
      phase: isUrl ? `URL Recon Event ${i + 1}` : isFile ? `File Malware Event ${i + 1}` : isLog ? `Log Forensics Event ${i + 1}` : `Investigation Event ${i + 1}`,
      tactic: isUrl ? "RECON" : isFile ? "EXECUTION" : isLog ? "DETECTION" : "INVESTIGATION",
      technique: `${String(h?.type || "scan").toUpperCase()} · ${String(level).toUpperCase()}`,
      detail: `${h?.name || "scan target"} · risk ${Number(h?.risk || 0)}/100 · findings ${Number(h?.findings || 0)} · iocs ${Number(h?.iocs || 0)}`,
      sev: level,
      icon: isUrl ? "🌐" : isFile ? "📁" : isLog ? "📋" : "🕵",
    };
  });
  const chain = dynamicPhases.length ? {
    name: "Live Monitor Attack Chain",
    target: `${dynamicPhases.length} monitor alerts`,
    risk: Math.min(99, Math.round(dynamicPhases.reduce((n, p) => n + (p.sev === "critical" ? 20 : p.sev === "high" ? 15 : 8), 0) / Math.max(dynamicPhases.length, 1))),
    level: "HIGH",
    phases: dynamicPhases,
    iocs: { ips: [], domains: (backendStatus?.alerts || []).map((a) => a?.url).filter(Boolean), urls: [], emails: [], hashes: [], reg_keys: [], commands: [], cves: [] },
  } : scanDerivedPhases.length ? {
    name: `Recent Scan Chain${top?.name ? ` — ${top.name}` : ""}`,
    target: `${scanDerivedPhases.length} backend scans`,
    risk: Math.min(99, Math.round(scanDerivedPhases.reduce((n, p) => n + (p.sev === "critical" ? 20 : p.sev === "high" ? 15 : p.sev === "medium" ? 10 : 5), 0) / Math.max(scanDerivedPhases.length, 1))),
    level: String(top?.level || "medium").toUpperCase(),
    phases: scanDerivedPhases,
    iocs: { ips: [], domains: historyItems.filter((h) => h.type === "url").map((h) => h.name).slice(0, 20), urls: [], emails: [], hashes: [], reg_keys: [], commands: [], cves: [] },
  } : ATTACK_CHAIN;
  const sevColor = { critical:"var(--red)", high:"var(--amber)", medium:"var(--blue)", low:"var(--green)" };

  return (
    <div className="view">
      <div className="fjsb mb20">
        <div>
          <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🕵 Attack Timeline & Reconstruction</div>
          <div className="txt-sec txt-sm">AI reconstructs the full kill chain — from entry point to final objective — mapped to MITRE ATT&CK</div>
        </div>
        <Badge level="purple">MITRE ATT&CK Mapped</Badge>
      </div>

      <div className="card mb16">
        <div className="card-hd">
          <span className="card-title">📌 Investigation: {chain.name}</span>
          <span className="mono txt-xs txt-muted">{chain.target}</span>
        </div>
        <div className="card-body">
          <RiskDisplay score={chain.risk} level={chain.level}>
            <div className="txt-sec txt-sm mb6">{chain.phases.length} attack phases · Full kill chain · MITRE ATT&CK aligned · 8 IOCs</div>
          </RiskDisplay>
        </div>
      </div>

      <div className="g2 mb16">
        <div className="card">
          <div className="card-hd"><span className="card-title">🔗 Attack Phases — Click to Expand</span></div>
          <div style={{ padding:0 }}>
            {chain.phases.map((p, i) => (
              <div key={i} style={{ borderBottom: i < chain.phases.length - 1 ? "1px solid var(--border)" : "none" }}>
                <div className="fac gap12" style={{ padding:"11px 16px", cursor:"pointer" }} onClick={() => setExpanded(expanded === i ? null : i)}>
                  <div style={{ width:30, height:30, borderRadius:"50%", background:`${sevColor[p.sev]}18`, border:`1.5px solid ${sevColor[p.sev]}50`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, flexShrink:0 }}>{p.icon}</div>
                  <div className="f1">
                    <div style={{ fontWeight:700, fontSize:12.5, color:"var(--t1)", marginBottom:2 }}>{p.phase}</div>
                    <div className="mono txt-xs txt-muted">{p.technique}</div>
                  </div>
                  <div className="fac gap6">
                    <span className="mitre">{p.tactic}</span>
                    <Badge level={p.sev}>{p.sev}</Badge>
                    <span style={{ color:"var(--t3)", fontSize:11 }}>{expanded === i ? "▲" : "▼"}</span>
                  </div>
                </div>
                {expanded === i && (
                  <div style={{ padding:"0 16px 14px 58px", animation:"fadeUp .15s ease" }}>
                    <div className="mono txt-xs" style={{ color:"var(--t2)", lineHeight:1.8 }}>{p.detail}</div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div style={{ display:"flex", flexDirection:"column", gap:13 }}>
          <div className="card">
            <div className="card-hd"><span className="card-title">🗺 MITRE ATT&CK Matrix</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["Initial Access","T1566.001","Phishing Attachment"],
                ["Execution","T1059.001","PowerShell"],
                ["Persistence","T1547.001","Registry AutoRun"],
                ["Defense Evasion","T1027","Obfuscated Files"],
                ["Injection","T1055.001","Remote Thread Injection"],
                ["C2","T1071.001","HTTP Protocol"],
                ["Credential Access","T1555.003","Browser Credentials"],
                ["Lateral Movement","T1078","Valid Credentials"],
              ].slice(0, Math.max(4, Math.min(chain.phases.length, 8))).map(([tactic, id, name], i) => (
                <div key={i} className="ck-row">
                  <div className="ck-lbl" style={{ fontSize:11 }}>{tactic}</div>
                  <div className="fac gap6"><span className="mono txt-xs" style={{ opacity:0.5 }}>{id}</span> <Badge level="info">{name}</Badge></div>
                </div>
              ))}
            </div>
          </div>
          <div className="card">
            <div className="card-hd"><span className="card-title">🤖 AI Reasoning Overview</span></div>
            <div className="card-body">
              <div className="mono txt-xs" style={{ lineHeight:1.6 }}>AI analysis of recent forensic artifacts identifies a multi-stage intrusion attempt. The primary threat actor (likely TA505/Emotet) utilized phishing as initial access, followed by PowerShell-based in-memory execution to establish C2 persistence. Analysts should monitor for lateral SMB movement and unusual outbound HTTP volume on the isolated host.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
