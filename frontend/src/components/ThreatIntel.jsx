import React, { useMemo } from "react";
import { Badge, Pbar, MITREGrid } from "./SOCLibrary";
import { HISTORY } from "./SOCConstants";
import { normalizeLevel } from "./SOCUtils";

const SEV_COL = { critical:"var(--red)", high:"var(--amber)", medium:"var(--blue)", low:"var(--green)", clean:"var(--green)" };

export function ThreatIntel({ backendStatus = {}, historyItems = HISTORY, onScanTrigger }) {
  /* ── provider status cards ── */
  const providers = [
    { name:"VirusTotal",  e:"🔬", desc:"URL & file reputation (72 engines)", key:"virustotal" },
    { name:"PhishTank",   e:"🎣", desc:"Community phishing database",        key:"phishtank" },
    { name:"AbuseIPDB",   e:"📡", desc:"IP abuse reports & blacklisting",    key:"abuseipdb" },
    { name:"URLScan.io",  e:"🔍", desc:"Dynamic page rendering analysis",    key:"urlscan" },
    { name:"OpenAI GPT",  e:"🤖", desc:"AI attack reconstruction engine",    key:"openai" },
    { name:"YARA Engine", e:"🛡", desc:"10,204 curated malware signatures",  key:"yara_engine" },
  ];
  const providerStatus = backendStatus?.provider_status || {};
  const yaraOk = backendStatus?.yara?.available === true;

  /* ── aggregate MITRE data from history + monitor alerts ── */
  const allMitre = useMemo(() => {
    const seen = new Map();
    historyItems.forEach(h => {
      (h.result?.mitre_mapping || []).forEach(m => {
        if (m.id && !seen.has(m.id)) seen.set(m.id, m);
      });
    });
    (backendStatus?.alerts || []).forEach(a => {
      (a.mitre_mapping || []).forEach(m => {
        if (m.id && !seen.has(m.id)) seen.set(m.id, m);
      });
    });
    return Array.from(seen.values()).slice(0, 12);
  }, [historyItems, backendStatus]);

  /* ── live feed from monitor alerts ── */
  const liveRows = (backendStatus?.alerts || []).slice(0, 10).map(a => ({
    ioc: a?.url || "watchlist-item",
    type: "Domain",
    family: a?.message || "Monitor alert",
    date: a?.timestamp ? new Date(a.timestamp).toLocaleDateString() : "—",
    src: "Monitor",
    conf: Math.min(99, Number(a?.risk_score || 50)),
    level: normalizeLevel(a?.threat_level || "medium"),
  }));

  /* ── fallback to scan history rows ── */
  const historyRows = historyItems.slice(0, 10).map(h => ({
    ioc: h?.name || "scan-target",
    type: String(h?.type || "scan").toUpperCase(),
    family: `${String(h?.level || "unknown").toUpperCase()} risk scan — ${h?.findings || 0} findings`,
    date: h?.date || "—",
    src: "GhostTrace",
    conf: Math.min(99, Number(h?.risk || 0)),
    level: normalizeLevel(h?.level || "medium"),
  }));

  const feedRows = liveRows.length ? liveRows : historyRows;

  /* ── threat family stats from history ── */
  const familyMap = {};
  historyItems.forEach(h => {
    const k = normalizeLevel(h?.level || "low");
    familyMap[k] = (familyMap[k] || 0) + 1;
  });
  const familyStats = [
    { n:"Critical Threats",   c: familyMap.critical || 0,  pb:"red",   p: Math.min(100, (familyMap.critical  || 0) * 20) },
    { n:"High Risk",          c: familyMap.high     || 0,  pb:"amber", p: Math.min(100, (familyMap.high      || 0) * 20) },
    { n:"Medium Risk",        c: familyMap.medium   || 0,  pb:"blue",  p: Math.min(100, (familyMap.medium    || 0) * 20) },
    { n:"Low / Clean",        c: familyMap.low + (familyMap.clean || 0) || 0, pb:"green", p: Math.min(100, ((familyMap.low || 0) + (familyMap.clean || 0)) * 20) },
  ].filter(f => f.c > 0);

  const demoFamilies = [
    { n:"Emotet Banking Trojan",       c:28, pb:"red",   p:35 },
    { n:"PayPal / BofA Phishing",      c:22, pb:"amber", p:27 },
    { n:"LockBit Ransomware",          c:14, pb:"red",   p:17 },
    { n:"RedLine Info Stealer",        c:11, pb:"blue",  p:14 },
    { n:"Crypto Mining Injector",      c:6,  pb:"green", p:7  },
  ];

  /* ── IOC extraction from history for origin summary ── */
  const allIPs = useMemo(() => {
    const ips = new Map();
    historyItems.forEach(h => {
      const result = h.result || {};
      const iocs = result.iocs || {};
      const ipList = Array.isArray(iocs) ? iocs.filter(i => i.type === "ip").map(i => i.value) : (iocs.ips || []);
      ipList.forEach(ip => { ips.set(ip, (ips.get(ip) || 0) + 1); });
    });
    (backendStatus?.alerts || []).forEach(a => {
      if (a.url) ips.set(a.url, (ips.get(a.url) || 0) + 1);
    });
    return Array.from(ips.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [historyItems, backendStatus]);

  const totalIOCs = allIPs.reduce((s, [, c]) => s + c, 0) || 1;

  const demoOrigins = [["🇷🇺 Russia","47","32%"],["🇨🇳 China","38","26%"],["🇧🇷 Brazil","21","14%"],["🇮🇷 Iran","18","12%"],["🇺🇸 USA (Proxied)","14","9%"],["🇳🇬 Nigeria","9","6%"]];

  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🌍 Threat Intelligence</div>
        <div className="txt-sec txt-sm">Connected feeds · Reputation APIs · YARA engine · IOC enrichment · MITRE mapping · Live threat data</div>
      </div>

      {/* Provider status cards */}
      <div className="g3 mb16">
        {providers.map(f => {
          const on = f.key === "yara_engine" ? yaraOk : Boolean(providerStatus[f.key]);
          return (
            <div key={f.name} className="card" style={{ padding:"14px" }}>
              <div className="fjsb mb6">
                <div className="fac gap8"><span style={{fontSize:18}}>{f.e}</span><span style={{fontWeight:700,fontSize:12}}>{f.name}</span></div>
                <Badge level={on ? "clean" : "medium"}>{on ? "Active" : "No Key"}</Badge>
              </div>
              <div className="mono txt-xs txt-muted mb8">{f.desc}</div>
              <Pbar val={on ? 100 : 30} color={on ? "green" : "amber"} />
            </div>
          );
        })}
      </div>

      {/* Live Threat Feed */}
      <div className="card mb16">
        <div className="card-hd">
          <span className="card-title">⚡ Live Threat Feed</span>
          <span className="fac gap6 mono txt-xs txt-muted"><span className="live-dot" />{liveRows.length ? "Live monitor alerts" : "From scan history"}</span>
        </div>
        <div style={{ padding:0 }}>
          <table className="tbl">
            <thead><tr><th>Indicator</th><th>Type</th><th>Classification</th><th>Date</th><th>Source</th><th>Action</th><th>Severity</th></tr></thead>
            <tbody>
              {feedRows.map((row, i) => (
                <tr key={i}>
                  <td><span className="hash-pill">{row.ioc}</span></td>
                  <td><Badge level={row.type === "URL" || row.type === "Domain" ? "info" : "purple"}>{row.type}</Badge></td>
                  <td style={{ color:"var(--t1)" }}>{row.family}</td>
                  <td className="mono txt-xs txt-muted">{row.date}</td>
                  <td className="txt-muted">{row.src}</td>
                  <td>
                    <button className="btn btn-primary btn-sm" style={{ padding:"2px 8px", fontSize:10 }}
                      onClick={() => onScanTrigger?.(row.type.toLowerCase(), row.ioc)}>Scan</button>
                  </td>
                  <td>
                    <div className="fac gap6">
                      <div className="lvl-dot" style={{ background: SEV_COL[row.level] || "var(--t3)" }} />
                      <Badge level={row.level}>{row.level.toUpperCase()}</Badge>
                    </div>
                  </td>
                </tr>
              ))}
              {feedRows.length === 0 && (
                <tr><td colSpan={7} style={{ textAlign:"center", color:"var(--t3)", padding:20 }}>No threat feed data. Run scans to populate.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* MITRE + Threat Families */}
      <div className="g2 mb16">
        <div className="card">
          <div className="card-hd"><span className="card-title">🗺 MITRE ATT&amp;CK® — Mapped Techniques</span></div>
          <div className="card-body">
            {allMitre.length > 0
              ? <MITREGrid mapping={allMitre} />
              : <div className="empty-state" style={{padding:"10px 0"}}>
                  <div className="empty-sub">MITRE techniques will appear here from scan results.</div>
                </div>
            }
          </div>
        </div>

        <div style={{ display:"flex", flexDirection:"column", gap:13 }}>
          <div className="card">
            <div className="card-hd"><span className="card-title">📊 Threat Severity Breakdown</span></div>
            <div className="card-body">
              {(familyStats.length ? familyStats : demoFamilies).map(r => (
                <div key={r.n} className="mb12">
                  <div className="fjsb mb6 mono txt-xs">
                    <span style={{ color: r.pb==="red"?"var(--red)":r.pb==="amber"?"var(--amber)":r.pb==="blue"?"var(--blue)":"var(--green)" }}>{r.n}</span>
                    <span className="txt-muted">{r.c} {familyStats.length ? "scans" : "samples"}</span>
                  </div>
                  <Pbar val={r.p} color={r.pb} />
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">🌐 Top Extracted IOCs / Origins</span></div>
            <div className="card-body" style={{ padding:0 }}>
              <table className="tbl">
                <thead><tr><th>Indicator / Host</th><th>Count</th><th>Share</th></tr></thead>
                <tbody>
                  {(allIPs.length
                    ? allIPs.map(([ip, cnt]) => [ip, String(cnt), `${Math.round((cnt/totalIOCs)*100)}%`])
                    : demoOrigins
                  ).map(([c, n, p], i) => (
                    <tr key={i}>
                      <td style={{color:"var(--t1)"}}><span className="hash-pill">{c}</span></td>
                      <td className="mono txt-xs" style={{color:"var(--amber)"}}>{n}</td>
                      <td className="mono txt-xs txt-muted">{p}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
