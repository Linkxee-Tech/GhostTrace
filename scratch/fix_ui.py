
import sys
import os

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Reconstruct helper components
helpers = """
const Spinner = () => <div className="spinner" />;

const Pbar = ({ val, color = "green" }) => (
  <div className="pbar">
    <div className={`pbar-fill pbar-${color}`} style={{ width: `${Math.min(val, 100)}%` }} />
  </div>
);

function Badge({ level, children }) {
  const l = (level || "info").toLowerCase();
  const map = {
    critical:"b-critical", high:"b-high", medium:"b-medium", low:"b-low",
    clean:"b-clean", info:"b-info", ip:"b-info", domain:"b-purple",
    md5:"b-high", sha256:"b-high", url:"b-url", email:"b-clean",
    file:"b-file", log:"b-log", ioc:"b-ioc", purple:"b-purple", pink:"b-pink",
  };
  return <span className={`badge ${map[l] || "b-info"}`}>{children || level}</span>;
}

function SecHd({ children }) {
  return <div className="sec-hd">{children}</div>;
}

function Terminal({ title, content }) {
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

function IOCPanel({ iocs }) {
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

function EntropyBar({ name, val, sus }) {
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

function RiskDisplay({ score, level, children }) {
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

function ThreatSeverityCard({ score, severity, confidence, type }) {
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

function IOCTable({ iocs }) {
  if (!iocs || iocs.length === 0) return null;
  const downloadIOCs = () => {
    const text = iocs.map(i => `${i.type},${i.value}`).join("\\n");
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
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((ioc, i) => (
              <tr key={i}>
                <td><Badge level={ioc.type}>{ioc.type}</Badge></td>
                <td className="mono tc-w">{ioc.value}</td>
                <td><div className="fac gap6"><span className="live-dot" /> <span className="mono txt-xs txt-muted">Pending Verification</span></div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ForensicTimeline({ events }) {
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

function MITREBoard({ mapping }) {
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

function HealthScoreRing({ scores }) {
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

function ScanProgress({ steps, cur, done }) {
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
"""

# Reconstruct missing functions
functions = """
function normalizeLevel(value) {
  const v = String(value || "").toLowerCase();
  if (["critical", "high", "medium", "low", "clean"].includes(v)) return v;
  if (v === "suspicious") return "medium";
  if (v === "safe") return "clean";
  return "medium";
}

function mapHistoryItem(doc, type) {
  const result = doc?.result || {};
  const risk = Number(doc?.risk_score ?? result?.risk?.score ?? result?.risk_score ?? 0);
  const level = normalizeLevel(doc?.severity ?? result?.risk?.severity ?? result?.threat_level);
  const iocs = result?.iocs || {};
  const iocCount = Object.values(iocs).reduce((acc, arr) => acc + ((arr && arr.length) || 0), 0);
  const findings = Array.isArray(result?.suspicious_strings)
    ? result.suspicious_strings.length
    : Array.isArray(result?.findings)
      ? result.findings.length
      : 0;
  return {
    id: doc?.id || `${type}-${Math.random()}`,
    type,
    name: doc?.filename || doc?.url || result?.filename || result?.input_url || `${type} scan`,
    level,
    risk,
    date: doc?.created_at ? new Date(doc.created_at).toLocaleString() : "-",
    findings,
    iocs: iocCount,
    ts: doc?.created_at ? new Date(doc.created_at).getTime() : 0,
  };
}

function severityFromText(text = "") {
  const t = String(text).toLowerCase();
  if (/(critical|rce|credential|exfil|malicious|phishing|backdoor)/.test(t)) return "critical";
  if (/(high|suspicious|obfuscat|expired|missing)/.test(t)) return "high";
  if (/(medium|warning|warn)/.test(t)) return "medium";
  return "low";
}

function mapUrlResult(data, scanUrl) {
  const iocMap = { ips: [], domains: [], urls: [], emails: [], hashes: [], reg_keys: [], commands: [], cves: [] };
  (data?.iocs || []).forEach((row) => {
    const t = String(row?.type || "").toLowerCase();
    if (!row?.value) return;
    if (t === "ip") iocMap.ips.push(row.value);
    else if (t === "domain") iocMap.domains.push(row.value);
    else if (t === "url") iocMap.urls.push(row.value);
    else if (t === "email") iocMap.emails.push(row.value);
  });

  const ssl = data?.reputation_signals?.ssl_certificate_analysis || {};
  const repSignals = data?.reputation_signals || {};
  const provider = repSignals?.provider_status || {};
  const domainRep = data?.threat_intel_mapping?.ip_reputation || "";
  const ipMatch = String(domainRep).match(/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/);
  const page = data?.page_artifacts || {};
  const findings = data?.findings || [];
  const vulnFindings = data?.vulnerability_findings || [];
  const injFindings = data?.malware_injection_findings || [];
  const recs = data?.recommendations || [];
  const health = data?.health_breakdown || {};

  const vulns = vulnFindings.map((v, i) => ({
    sev: severityFromText(v),
    name: `Detected Vulnerability ${i + 1}`,
    cve: "CWE-693",
    evidence: v,
    fix: recs[0] || "Apply defensive hardening and patch exposed components.",
  }));

  const injections = injFindings.map((v) => ({
    sev: severityFromText(v),
    icon: "💉",
    title: "Malware Injection Indicator",
    detail: v,
  }));

  const checks = [
    { n: "Threat Level", v: String(data?.threat_level || "unknown").toUpperCase(), ok: false },
    { n: "Risk Score", v: `${Number(data?.risk_score ?? 0)}/100`, ok: Number(data?.risk_score ?? 0) < 35 },
    { n: "Suspicious Behaviors", v: String(data?.suspicious_behaviors_detected ?? 0), ok: Number(data?.suspicious_behaviors_detected ?? 0) === 0 },
    { n: "TLS Status", v: ssl?.status || "Unknown", ok: ssl?.status === "Certificate valid" },
    { n: "Page Scripts", v: `${page?.script_count ?? 0} scripts`, ok: (page?.script_count ?? 0) < 10 },
    { n: "Hidden IFrames", v: `${page?.hidden_iframe_count ?? 0}`, ok: (page?.hidden_iframe_count ?? 0) === 0 },
  ];

  const totalRisk = Number(data?.risk_score ?? 0);
  const vtScore = Number(data?.reputation_signals?.urlscan?.score ?? 0);
  const abuseScoreMatch = String(domainRep).match(/score\\s+(\\d+)\\/100/i);
  const abuseScore = abuseScoreMatch ? Number(abuseScoreMatch[1]) : null;
  const safeIocs = { ips: [], domains: [], urls: [], emails: [], hashes: [], reg_keys: [], commands: [], cves: [] };
  
  return {
    url: data?.input_url || scanUrl,
    ip: iocMap.ips[0] || ipMatch?.[0] || "N/A",
    country: "N/A",
    isp: "N/A",
    domain_age: "N/A",
    registrar: "N/A",
    redirects: [data?.input_url || scanUrl || "N/A"],
    ssl: {
      valid: ssl?.has_tls || false,
      issuer: ssl?.issuer || "Unknown",
      expiry: ssl?.not_after || "Unknown",
    },
    tech: (data?.website_compromise_indicators || data?.findings || []).slice(0, 4),
    rep: {
      vt: provider?.virustotal ? (vtScore || "Configured") : "Not configured",
      urlscan: repSignals?.urlscan?.verdict === true ? "Malicious" : repSignals?.urlscan?.verdict === false ? "No-malicious verdict" : "Unavailable",
      abuseipdb: abuseScore ?? (provider?.abuseipdb ? "Configured" : "Not configured"),
      phishtank: provider?.phishtank ? "Configured" : "Not configured",
    },
    checks,
    injections,
    vulns,
    health: {
      total: Math.max(0, 100 - totalRisk),
      ssl: Math.round((Number(health?.ssl_security ?? 0) / 100) * 20),
      malware: Math.round((Number(health?.malware_presence ?? 0) / 100) * 30),
      vulns: Math.round((Number(health?.vulnerability_exposure ?? 0) / 100) * 20),
      rep: Math.round((Number(health?.reputation ?? 0) / 100) * 15),
      content: Math.round((Number(health?.content_integrity ?? 0) / 100) * 15),
    },
    content: {
      login_form: (page?.suspicious_form_count ?? 0) > 0,
      pass_field: (page?.suspicious_form_count ?? 0) > 0,
      form_action: "Derived from backend page analysis",
      hidden_iframes: page?.hidden_iframe_count ?? 0,
      obfuscated_js: (page?.suspicious_script_patterns || []).length > 0,
      ext_scripts: page?.external_script_samples || [],
    },
    iocs: { ...safeIocs, ...iocMap },
    risk: totalRisk,
    level: String(data?.threat_level || "unknown").toUpperCase(),
    ai: data?.threat_explanation || "No AI explanation available for this scan.",
    url_timeline: findings.slice(0, 5).map((f, idx) => ({
      t: `Event ${idx + 1}`,
      e: "Backend Finding",
      d: f,
      sev: severityFromText(f),
    })),
  };
}

function mapLogResult(data, scanText) {
  const patterns = data?.behavior_patterns || [];
  const timeline = patterns.map((p, i) => ({
    t: `Stage ${i + 1}`,
    e: p,
    d: `Detected behavior pattern: ${p}`,
    sev: severityFromText(p),
  }));
  const suspicious = patterns.length;
  return {
    ...D_LOG,
    lines: scanText.split(/\\r?\\n/).filter(Boolean).length,
    suspicious,
    critical: String(data?.threat_level || "").toLowerCase() === "critical" ? Math.max(1, suspicious) : Math.min(suspicious, 2),
    anomalies: suspicious,
    risk: Number(data?.risk_score ?? D_LOG.risk),
    level: String(data?.threat_level || "high").toUpperCase(),
    iocs: {
      ips: data?.iocs?.ips || [],
      domains: data?.iocs?.domains || [],
      commands: data?.iocs?.suspicious_commands || [],
    },
    ai: data?.ai_explanation || D_LOG.ai,
    timeline: timeline.length ? timeline : D_LOG.timeline,
  };
}
"""

# Identify the broken part
start_marker = "function downloadJson(data, filename) {"
end_marker = "function useScan(steps) {"

start_idx = -1
end_idx = -1

for i, line in enumerate(lines):
    if start_marker in line:
        start_idx = i
    if end_marker in line:
        end_idx = i
        break

if start_idx != -1 and end_idx != -1:
    new_content = lines[:start_idx+3] + [functions, helpers] + lines[end_idx:]
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(new_content)
    print("Successfully restored GhostTrace.jsx")
else:
    print(f"Failed to find markers: start={start_idx}, end={end_idx}")
