import React from "react";

export const Spinner = () => <div className="spinner" />;

export const Pbar = ({ val, color = "green" }) => (
  <div className="pbar">
    <div className={`pbar-fill pbar-${color}`} style={{ width: `${Math.min(val, 100)}%` }} />
  </div>
);

export function Badge({ level, children }) {
  const l = (level || "info").toLowerCase();
  const map = {
    critical:"b-critical", high:"b-high", medium:"b-medium", low:"b-low",
    clean:"b-clean", info:"b-info", ip:"b-info", domain:"b-purple",
    md5:"b-high", sha256:"b-high", url:"b-url", email:"b-clean",
    file:"b-file", log:"b-log", ioc:"b-ioc", purple:"b-purple", pink:"b-pink",
  };
  return <span className={`badge ${map[l] || "b-info"}`}>{children || level}</span>;
}

export function SecHd({ children }) {
  return <div className="sec-hd">{children}</div>;
}

export function Terminal({ title, content }) {
  return (
    <div className="terminal">
      <div className="term-bar">
        <div className="term-dots">
          <div className="term-dot" style={{ background: "#ff5f57" }} />
          <div className="term-dot" style={{ background: "#febc2e" }} />
          <div className="term-dot" style={{ background: "#28c840" }} />
        </div>
        <span className="term-label">⬡ GhostTrace AI — {title}</span>
      </div>
      <div className="term-body" dangerouslySetInnerHTML={{ __html: content }} />
    </div>
  );
}

export function ThreatSeverityCard({ score, severity, confidence, type }) {
  const sev = (severity || "low").toLowerCase();
  const Icon = { critical: "☢️", high: "⚠️", medium: "🔍", low: "✅", clean: "🛡️" }[sev] || "🔍";
  return (
    <div className={`threat-card-soc ${sev}`}>
      <div className="soc-score-circle">
        <span className={`soc-score-val txt-${sev}`}>{score}</span>
        <span className="mono txt-muted" style={{ fontSize: 8 }}>RISK</span>
      </div>
      <div className="f1">
        <div className="fac gap8 mb4">
          <Badge level={sev}>{severity}</Badge>
          <span className="mono txt-muted txt-xs" style={{ letterSpacing: 1 }}>{type?.toUpperCase() || 'SCAN'} ANALYSIS</span>
        </div>
        <div className="txt-sec txt-sm">Confidence: <span className="tc-c">{confidence}%</span> based on automated forensics</div>
      </div>
      <div style={{ fontSize: 24, opacity: 0.2 }}>{Icon}</div>
    </div>
  );
}

export function IOCTable({ iocs, onScanTrigger }) {
  if (!iocs || iocs.length === 0) return null;
  const downloadIOCs = () => {
    const text = iocs.map(i => `${i.type},${i.value}`).join("\n");
    const blob = new Blob([text], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "ghosttrace_iocs.csv"; a.click();
  };
  return (
    <div className="ioc-table-wrap">
      <div className="ioc-table-header">
        <div className="fac gap8">
          <span style={{ fontSize: 16 }}>🔗</span>
          <span className="mono bold txt-xs" style={{ letterSpacing: 1 }}>EXTRACTED INDICATORS ({iocs.length})</span>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={downloadIOCs}>⬇ Export CSV</button>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table className="ioc-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Indicator Value</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((ioc, i) => (
              <tr key={i}>
                <td><Badge level={ioc.type}>{ioc.type}</Badge></td>
                <td className="mono tc-w">{ioc.value}</td>
                <td>
                  <div className="fac gap8">
                    <button className="btn btn-primary btn-sm" style={{ padding: "2px 8px", fontSize: 10 }} onClick={() => onScanTrigger?.(ioc.type, ioc.value)}>Scan</button>
                    <div className="fac gap6"><span className="live-dot" /> <span className="mono txt-xs txt-muted">Pending Verification</span></div>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function ForensicTimeline({ events }) {
  if (!events || events.length === 0) return null;
  return (
    <div className="timeline-forensic">
      {events.map((ev, i) => (
        <div key={i} className={`timeline-node ${ev.sev || "low"}`}>
          <div className="timeline-node-content">
            <span className="timeline-node-stage">{ev.stage}</span>
            <div className="timeline-node-details">{ev.details}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

export function MITREBoard({ mapping }) {
  if (!mapping || mapping.length === 0) return null;
  return (
    <div className="mb20">
      <SecHd>MITRE ATT&CK Mapping</SecHd>
      <div className="fac gap8" style={{ flexWrap: "wrap" }}>
        {mapping.map((m, i) => (
          <div key={i} className="mitre-badge-lg">
            <span style={{ opacity: 0.5 }}>{m.id}</span> {m.technique}
          </div>
        ))}
      </div>
    </div>
  );
}

export function HealthScoreRing({ scores }) {
  if (!scores) return null;
  const vals = Object.values(scores);
  const average = vals.length ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : 0;
  const getCol = (s) => s >= 80 ? "var(--green)" : s >= 50 ? "var(--amber)" : "var(--red)";
  return (
    <div className="hs-wrap">
      <div className="hs-circle" style={{ border: `3px solid ${getCol(average)}`, boxShadow: `0 0 24px ${getCol(average)}33` }}>
        <span className="hs-score-val" style={{ color: getCol(average) }}>{average}</span>
        <span className="hs-score-max">HEALTH</span>
      </div>
      <div className="hs-bars">
        {Object.entries(scores).map(([label, val]) => (
          <div key={label} className="hs-bar-row">
            <div className="hs-bar-lbl mono txt-xs">{label.toUpperCase()}</div>
            <div className="hs-bar-track">
              <div className="hs-bar-fill" style={{ width: `${val}%`, background: getCol(val) }} />
            </div>
            <div className="hs-bar-val mono" style={{ color: getCol(val) }}>{val}%</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function IOCPanel({ iocs }) {
  if (!iocs) return null;
  const secs = [
    { key:"ips",     label:"IP Addresses",        cls:"ioc-ip",     icon:"🔌" },
    { key:"domains", label:"Domains",             cls:"ioc-domain", icon:"🌐" },
    { key:"urls",    label:"Malicious URLs",       cls:"ioc-url",    icon:"🔗" },
    { key:"hashes",  label:"File Hashes",          cls:"ioc-hash",   icon:"🔐" },
    { key:"emails",  label:"Email Addresses",      cls:"ioc-email",  icon:"✉"  },
    { key:"reg_keys",label:"Registry Keys",        cls:"ioc-reg",    icon:"⚙"  },
    { key:"commands",label:"Suspicious Commands",  cls:"ioc-cmd",    icon:"💻" },
    { key:"cves",    label:"CVEs / CWEs",          cls:"ioc-cve",    icon:"⚠"  },
  ];
  const any = secs.some(s => (iocs[s.key] || []).length > 0);
  if (!any) return (
    <div className="empty-state">
      <div className="empty-icon">🔎</div>
      <div className="empty-title">No IOCs detected</div>
      <div className="empty-sub">No indicators of compromise were found in this input.</div>
    </div>
  );
  return (
    <div>
      {secs.map(s => {
        const items = iocs[s.key] || [];
        if (!items.length) return null;
        return (
          <div key={s.key} className="mb16">
            <SecHd>{s.label} ({items.length})</SecHd>
            <div className="ioc-grid">
              {items.map((v, i) => (
                <span key={i} className={`ioc ${s.cls}`}>
                  {s.icon} {v.length > 64 ? v.slice(0, 64) + "…" : v}
                </span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function EntropyBar({ name, val, sus }) {
  const pct = Math.min((val / 8) * 100, 100);
  const color = val > 7.5 ? "var(--red)" : val > 6.5 ? "var(--amber)" : "var(--green)";
  return (
    <div className="ent-row">
      <div className="ent-hd">
        <span style={{ color: "var(--t2)" }}>{name}</span>
        <span style={{ color }}>{val.toFixed(2)} {sus && "⚠"}</span>
      </div>
      <div className="ent-bar">
        <div className="ent-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

export function RiskDisplay({ score, level, children }) {
  const l = (level || "").toLowerCase();
  return (
    <div className="risk-wrap">
      <div className={`risk-ring ${l}`}>
        <span className={`risk-num ${l}`}>{score}</span>
        <span className="risk-denom">/ 100</span>
      </div>
      <div className="f1">
        <div className="fac gap8 mb8">
          <span className="mono txt-xs txt-muted" style={{ letterSpacing: 1 }}>THREAT SCORE</span>
          <Badge level={l}>{level}</Badge>
        </div>
        {children}
      </div>
    </div>
  );
}

export function ScanProgress({ steps, cur, done }) {
  const pct = Math.round((done.length / steps.length) * 100);
  return (
    <div>
      <div className="fac gap12 mb20">
        <Spinner />
        <div className="f1">
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6 }}>Scanning in progress…</div>
          <Pbar val={pct} />
        </div>
        <span className="mono txt-xs txt-muted">{pct}%</span>
      </div>
      <div className="scan-steps">
        {steps.map((s, i) => {
          const isDone = done.includes(i);
          const isRun = cur === i && !isDone;
          const st = isDone ? "done" : isRun ? "running" : "pending";
          return (
            <div key={i} className="s-step">
              <div className="s-ic">
                {isDone
                  ? <span style={{ color: "var(--green)" }}>✓</span>
                  : isRun ? <Spinner />
                  : <span style={{ color: "var(--t3)" }}>○</span>}
              </div>
              <div className={`s-lbl ${st}`}>{s.label}</div>
              <div className={`s-stat ${st}`}>{isDone ? "Done" : isRun ? "Running…" : "Queued"}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function Toggle({ on, onChange }) {
  return (
    <div className={`toggle-wrap ${on ? "on" : ""}`} onClick={onChange}>
      <div className="toggle-knob" />
    </div>
  );
}

/* ─── Investigation Workflow pipeline display ─── */
const WORKFLOW_STEPS = [
  { icon: "📥", label: "Input" },
  { icon: "✅", label: "Validate" },
  { icon: "🔍", label: "Scan" },
  { icon: "🧩", label: "Enrich" },
  { icon: "🤖", label: "Analyze" },
  { icon: "📊", label: "Visualize" },
  { icon: "📑", label: "Report" },
];

export function InvestigationWorkflow({ activeStep = -1 }) {
  return (
    <div className="inv-workflow">
      {WORKFLOW_STEPS.map((s, i) => (
        <React.Fragment key={i}>
          <div className="inv-step">
            <div className={`inv-step-icon${i < activeStep ? " done" : i === activeStep ? " active" : ""}`}>{s.icon}</div>
            <div className={`inv-step-label${i < activeStep ? " done" : i === activeStep ? " active" : ""}`}>{s.label}</div>
          </div>
          {i < WORKFLOW_STEPS.length - 1 && <div className={`inv-connector${i < activeStep ? " done" : ""}`} />}
        </React.Fragment>
      ))}
    </div>
  );
}

/* ─── MITRE ATT&CK grid (improved) ─── */
export function MITREGrid({ mapping }) {
  if (!mapping || mapping.length === 0) return (
    <div className="empty-state" style={{ padding: "12px 0" }}>
      <div className="empty-sub">No MITRE ATT&amp;CK techniques mapped for this scan.</div>
    </div>
  );
  return (
    <div className="mitre-grid">
      {mapping.map((m, i) => (
        <div key={i} className="mitre-cell">
          <span className="mitre-id">{m.id}</span>
          <span className="mitre-name">{m.technique}</span>
        </div>
      ))}
    </div>
  );
}

/* ─── Risk gauge ring ─── */
export function RiskGauge({ score, severity, confidence, label }) {
  const sev = (severity || "low").toLowerCase();
  const sevCol = { critical: "var(--red)", high: "var(--amber)", medium: "var(--blue)", low: "var(--green)", clean: "var(--green)" };
  const col = sevCol[sev] || "var(--t3)";
  return (
    <div className="risk-gauge">
      <div className={`risk-gauge-ring ${sev}`}>
        <span className="risk-gauge-num" style={{ color: col }}>{score}</span>
        <span className="risk-gauge-denom">/100</span>
      </div>
      <div className="risk-gauge-info">
        <div className="risk-gauge-title">{label || "Risk Score"}</div>
        <div className="risk-gauge-sub" style={{ color: col }}>{String(severity || "").toUpperCase()} THREAT</div>
        {confidence != null && (
          <div className="conf-meter">
            <div className="conf-track"><div className="conf-fill" style={{ width: `${confidence}%` }} /></div>
            <span className="conf-val">{confidence}%</span>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Confidence meter (standalone) ─── */
export function ConfidenceMeter({ value, label }) {
  return (
    <div className="conf-meter" style={{ marginTop: 0 }}>
      {label && <span className="mono txt-xs txt-muted" style={{ minWidth: 80 }}>{label}</span>}
      <div className="conf-track"><div className="conf-fill" style={{ width: `${value || 0}%` }} /></div>
      <span className="conf-val">{value || 0}%</span>
    </div>
  );
}
