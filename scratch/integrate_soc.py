
import sys
import os

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update FileScanner State Mapping
content = content.replace(
    "ai: data.ai_summary || D_FILE.ai,",
    "ai: data.ai_summary || D_FILE.ai,\\n          mitre_mapping: data.mitre_mapping || [],"
)

# 2. Update FileScanner Result View
content = content.replace(
    """          <RiskDisplay score={r.risk} level={r.level}>
            <div className="txt-sec txt-sm mb6">{r.yara.length} YARA rules matched · {r.imports.length} suspicious API imports · Persistence mechanism detected</div>
            <div className="mono txt-xs txt-muted">Engine: GhostTrace AI v2.0 + YARA 4.3 · Confidence: 94%</div>
          </RiskDisplay>""",
    """          <div className="mb20">
            <ThreatSeverityCard score={r.risk} severity={r.level} confidence={94} type="file" />
          </div>"""
)

content = content.replace(
    '<div className="card-hd"><span className="card-title">📁 File Metadata</span></div>',
    '<MITREBoard mapping={r.mitre_mapping || []} />\\n              <div className="card">'
)

content = content.replace(
    '<div className="card-body"><IOCPanel iocs={r.iocs} /></div>',
    '<div className="card-body"><IOCTable iocs={Object.entries(r.iocs || {}).flatMap(([type, vals]) => (vals || []).map(v => ({ type, value: v })))} /></div>'
)

# 3. Update URLScanner Result View
content = content.replace(
    """          <RiskDisplay score={r.risk} level={r.level}>
            <div className="txt-sec txt-sm mb6">{String(r.level || "").toUpperCase()} risk · {r.vulns.length} vulnerability findings · {r.injections.length} injection indicators · {r.iocs?.domains?.length || 0} related domains</div>
            <div className="mono txt-xs txt-muted">Sources: VirusTotal · PhishTank · AbuseIPDB · URLScan.io · GhostTrace AI</div>
          </RiskDisplay>""",
    """          <div className="mb20">
            <ThreatSeverityCard score={r.risk} severity={r.level} confidence={88} type="url" />
          </div>"""
)

content = content.replace(
    """          {tab === "health" && (
            <>
              <div className="hs-wrap">
                <div style={{ textAlign:"center" }}>
                  <div className="hs-circle" style={{ background:"rgba(255,45,85,.08)", border:"3px solid rgba(255,45,85,.4)", boxShadow:"0 0 32px rgba(255,45,85,.2)" }}>
                    <span className="hs-score-val" style={{ color:"var(--red)" }}>{r.health.total}</span>
                    <span className="hs-score-max">/100</span>
                  </div>
                  <Badge level={riskState}>{String(r.level || riskState).toUpperCase()} RISK</Badge>
                </div>
                <div className="hs-bars">
                  {[
                    { l:"SSL Security",       s:r.health.ssl,     max:20, c:"red"   },
                    { l:"Malware Presence",   s:r.health.malware, max:30, c:"red"   },
                    { l:"Vulnerability Score",s:r.health.vulns,   max:20, c:"amber" },
                    { l:"Reputation Score",   s:r.health.rep,     max:15, c:"red"   },
                    { l:"Content Integrity",  s:r.health.content, max:15, c:"red"   },
                  ].map(b => (
                    <div key={b.l} className="hs-bar-row">
                      <div className="hs-bar-lbl">{b.l}</div>
                      <div className="hs-bar-track">
                        <div className="hs-bar-fill" style={{ width:`${Math.min((b.s/b.max)*100,100)}%`, background: b.c==="red"?"var(--red)":b.c==="amber"?"var(--amber)":"var(--green)" }} />
                      </div>
                      <div className="hs-bar-val" style={{ color: b.c==="red"?"var(--red)":b.c==="amber"?"var(--amber)":"var(--green)" }}>{b.s}/{b.max}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="g3">
                {[
                  {t:"SSL Security",    s:`${r.health.ssl}/20`,     g:r.health.ssl < 8 ? "F" : r.health.ssl < 14 ? "D" : "B", desc:`TLS issuer: ${r.ssl?.issuer || "Unknown"}, expiry: ${r.ssl?.expiry || "Unknown"}.`,c:r.health.ssl < 10 ? "red" : "amber"},
                  {t:"Malware Presence",s:`${r.health.malware}/30`, g:r.health.malware < 12 ? "F" : r.health.malware < 20 ? "D" : "B", desc:`${r.injections.length} malware/injection indicators found from backend analysis.`,c:r.health.malware < 15 ? "red" : "amber"},
                  {t:"Vulnerabilities", s:`${r.health.vulns}/20`,   g:r.health.vulns < 8 ? "F" : r.health.vulns < 14 ? "D" : "B", desc:`${r.vulns.length} vulnerability findings and ${r.checks.length} security checks evaluated.`,c:r.health.vulns < 10 ? "red" : "amber"},
                  {t:"Reputation",      s:`${r.health.rep}/15`,     g:r.health.rep < 6 ? "F" : r.health.rep < 10 ? "D" : "B", desc:`VT: ${String(r.rep?.vt ?? "N/A")}, AbuseIPDB: ${String(r.rep?.abuseipdb ?? "N/A")}, URLScan: ${String(r.rep?.urlscan ?? "N/A")}.`,c:r.health.rep < 8 ? "red" : "amber"},
                  {t:"Content Integrity",s:`${r.health.content}/15`,g:r.health.content < 6 ? "F" : r.health.content < 10 ? "D" : "B", desc:`Hidden iframes: ${r.content.hidden_iframes}, obfuscated JS: ${r.content.obfuscated_js ? "yes" : "no"}.`,c:r.health.content < 8 ? "red" : "amber"},
                ].map(b => (
                  <div key={b.t} className="card" style={{ padding:"14px 16px" }}>
                    <div className="fjsb mb6"><span style={{ fontWeight:700, fontSize:12.5 }}>{b.t}</span><span className="mono" style={{ fontSize:22, fontWeight:700, color:b.c==="red"?"var(--red)":b.c==="amber"?"var(--amber)":"var(--green)" }}>{b.g}</span></div>
                    <div className="mono txt-xs txt-muted mb6">{b.s} points</div>
                    <div style={{ fontSize:11, color:"var(--t2)", lineHeight:1.65 }}>{b.desc}</div>
                  </div>
                ))}
              </div>
            </>
          )}""",
    """          {tab === "health" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">🏥 Cyber Health Assessment</span></div>
              <div className="card-body">
                <HealthScoreRing scores={{
                  "SSL Security": Math.round((r.health.ssl / 20) * 100),
                  "Malware Risk": Math.round((r.health.malware / 30) * 100),
                  "Vulnerabilities": Math.round((r.health.vulns / 20) * 100),
                  "Reputation": Math.round((r.health.rep / 15) * 100),
                  "Content": Math.round((r.health.content / 15) * 100),
                }} />
              </div>
            </div>
          )}"""
)

content = content.replace(
    'setResult(mapUrlResult(data, scanUrl));',
    'setResult({ ...mapUrlResult(data, scanUrl), mitre_mapping: data.mitre_mapping || [] });'
)

# 4. Update LogAnalyzer Result View
content = content.replace(
    """          <RiskDisplay score={r.risk} level={r.level}>
            <div className="txt-sec txt-sm mb6">Full attack lifecycle — Brute Force → Root Compromise → Persistence → C2 → Lateral Movement → Exfiltration → Log Wipe</div>
            <div className="mono txt-xs txt-muted">GhostTrace SIEM Engine + AI · {r.anomalies} behavioral anomalies detected</div>
          </RiskDisplay>""",
    """          <div className="mb20">
            <ThreatSeverityCard score={r.risk} severity={r.level} confidence={92} type="log" />
          </div>"""
)

content = content.replace(
    'setResult(mapLogResult(data, scanText));',
    'setResult({ ...mapLogResult(data, scanText), mitre_mapping: data.mitre_mapping || [] });'
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Successfully integrated SOC components into GhostTrace.jsx")
