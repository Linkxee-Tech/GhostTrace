import React, { useState, useEffect, useCallback } from "react";
import { Spinner, ThreatSeverityCard, IOCTable, Terminal, ScanProgress } from "./SOCLibrary";
import { D_LOG, LOG_STEPS, DEMO_LOGS } from "./SOCConstants";
import { useScan, apiJson, apiBlob, downloadBlob, reportClientError, mapLogResult } from "./SOCUtils";

export function LogAnalyzer({ pendingScan, setPendingScan, onScanTrigger, onScanComplete }) {
  const { phase, cur, done, start, reset } = useScan(LOG_STEPS);
  const [text, setText] = useState("");
  const [tab, setTab] = useState("timeline");
  const [scanText, setScanText] = useState("");
  const [result, setResult] = useState(D_LOG);
  const r = result;

  const go = useCallback(() => { setScanText(text); start(); }, [start, text]);
  const resetAll = () => { reset(); setTab("timeline"); };

  useEffect(() => {
    if (phase !== "done" || !scanText?.trim()) return;
    (async () => {
      try {
        const data = await apiJson("/api/analyze-log", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ log_text: scanText }) });
        setResult({ ...mapLogResult(data, scanText), mitre_mapping: data.mitre_mapping || [] });
        if (typeof onScanComplete === "function") await onScanComplete();
      } catch (e) { reportClientError("Log analysis failed", e); }
    })();
  }, [phase, scanText, onScanComplete]);

  return (
    <div className="view">
      {phase === "idle" && (
        <>
          <div className="mb20">
            <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>📋 Log Analyzer</div>
            <div className="txt-sec txt-sm">Detect brute force · Privilege escalation · C2 beacons · Lateral movement · Exfiltration · Log tampering</div>
          </div>
          <div className="card mb16">
            <div className="card-body">
              <label className="inp-label">Paste Log Content</label>
              <textarea className="inp textarea w100 mb12" style={{ height:180, fontSize:11, lineHeight:1.7 }} placeholder="Paste auth.log, syslog, Apache access.log, Windows Event logs, firewall logs, or any raw log format…" value={text} onChange={e => setText(e.target.value)} />
              <div className="fac gap8">
                <button className="btn btn-primary" onClick={go}>🔍 Analyze Logs</button>
                <button className="btn btn-sec" onClick={() => { setText(DEMO_LOGS); setTimeout(go, 100); }}>Load Demo Logs</button>
                <button className="btn btn-ghost" onClick={() => setText("")}>Clear</button>
                <span className="mono txt-xs txt-muted" style={{ marginLeft:"auto" }}>Supports: auth.log · syslog · access.log · firewall · WinEvent</span>
              </div>
            </div>
          </div>
          <div className="feat-grid mb18">
            {[{e:"🔐",n:"Brute Force Detection",d:"Failed login storms, rate & pattern anomalies"},
              {e:"⬆",n:"Privilege Escalation",d:"sudo abuse, NOPASSWD, SUID exploitation"},
              {e:"📡",n:"C2 Beacon Patterns",d:"Periodic outbound requests, beacon timing analysis"},
              {e:"↔",n:"Lateral Movement",d:"Internal SSH, SMB, RDP anomaly detection"},
              {e:"📦",n:"Data Exfiltration",d:"Unusual outbound volume spikes, dump patterns"},
              {e:"🗑",n:"Log Tampering",d:"rm -rf /var/log, cleared Event Log detection"},
            ].map(f => <div key={f.n} className="feat-card"><div className="feat-icon">{f.e}</div><div className="feat-name">{f.n}</div><div className="feat-desc">{f.d}</div></div>)}
          </div>
        </>
      )}

      {phase === "scanning" && (
        <div className="card">
          <div className="card-hd"><span className="card-title fac gap8"><Spinner /> Analyzing logs…</span></div>
          <div className="card-body"><ScanProgress steps={LOG_STEPS} cur={cur} done={done} /></div>
        </div>
      )}

      {phase === "done" && (
        <>
          <div className="fjsb gap12 mb20">
            <div>
              <div style={{ fontSize:18, fontWeight:800, marginBottom:4 }}>Log Analysis Complete</div>
              <div className="mono txt-xs txt-muted">{r.lines.toLocaleString()} lines analyzed · {r.suspicious} suspicious events · {r.critical} critical</div>
            </div>
            <div className="fac gap8">
              <button className="btn btn-ghost" onClick={resetAll}>↩ New Analysis</button>
              <button className="btn btn-primary" onClick={async () => { const logText = scanText || text || DEMO_LOGS; if (!logText?.trim()) return; try { const blob = await apiBlob("/api/generate-log-report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ log_text: logText }) }); downloadBlob(blob, "ghosttrace_log_report.pdf"); } catch (e) { reportClientError("Log report download failed", e); } }}>⬇ Download PDF</button>
            </div>
          </div>

          <div className="mb20">
            <ThreatSeverityCard score={r.risk} severity={r.level} confidence={92} type="log" />
          </div>

          <div className="g3 mb16">
            <div className="stat c-red"><div className="stat-val" style={{color:"var(--red)"}}>{r.critical}</div><div className="stat-lbl">Critical Events</div></div>
            <div className="stat c-amber"><div className="stat-val" style={{color:"var(--amber)"}}>{r.suspicious}</div><div className="stat-lbl">Suspicious Events</div></div>
            <div className="stat c-cyan"><div className="stat-val" style={{color:"var(--cyan)"}}>{r.anomalies}</div><div className="stat-lbl">Behavioral Anomalies</div></div>
          </div>

          <div className="tabs">
            {[["timeline","📅 Event Timeline"],["iocs","🔗 IOCs"],["ai","🤖 AI Attack Chain"]].map(([id, lbl]) => (
              <button key={id} className={`tab ${tab === id ? "on" : ""}`} onClick={() => setTab(id)}>{lbl}</button>
            ))}
          </div>

          {tab === "timeline" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">📅 Forensic Event Timeline</span></div>
              <div className="card-body">
                <div className="tl-wrap">
                  {r.timeline.map((ev, i) => (
                    <div key={i} className={`tl-event ${ev.sev}`}>
                      <div className="tl-time">{ev.t}</div>
                      <div className="tl-card">
                        <div className="tl-title">{ev.e}</div>
                        <div className="tl-body">{ev.d}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {tab === "iocs" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">🔗 IOCs Extracted from Logs</span></div>
              <div className="card-body"><IOCTable iocs={Object.entries(r.iocs || {}).flatMap(([type, vals]) => (vals || []).map(v => ({ type, value: v })))} onScanTrigger={onScanTrigger} /></div>
            </div>
          )}

          {tab === "ai" && <Terminal title="Log Forensics Analysis — Attack Chain Reconstruction" content={r.ai} />}
        </>
      )}
    </div>
  );
}
