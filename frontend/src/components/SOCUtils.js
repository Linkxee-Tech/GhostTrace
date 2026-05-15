import { useState, useCallback } from "react";
import { D_LOG } from "./SOCConstants";

export const API_BASE = (import.meta.env.VITE_GHOSTTRACE_API_BASE || "http://localhost:8000").replace(/\/+$/, "");
let RUNTIME_API_KEY = (import.meta.env.VITE_GHOSTTRACE_API_KEY || "").trim();
export const API_STORAGE_KEY = "ghosttrace.settings.apiKeys.v1";
export const SETTINGS_STORAGE_KEY = "ghosttrace.settings.toggles.v1";

export function setRuntimeApiKey(value) {
  RUNTIME_API_KEY = String(value || "").trim();
}

export function reportClientError(context, error) {
  const msg = error?.message || String(error || "Unknown error");
  console.error(`[GhostTrace] ${context}: ${msg}`, error);
}

export function apiHeaders(extra = {}) {
  return RUNTIME_API_KEY ? { ...extra, "x-api-key": RUNTIME_API_KEY } : extra;
}

export async function apiJson(path, init = {}) {
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers: apiHeaders(init.headers || {}) });
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = body?.detail ? ` - ${body.detail}` : "";
    } catch {}
    const err = new Error(`API ${path} failed: ${res.status}${detail}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function apiBlob(path, init = {}) {
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers: apiHeaders(init.headers || {}) });
  if (!res.ok) {
    const err = new Error(`API ${path} failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.blob();
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function openBlobInNewTab(blob) {
  const url = URL.createObjectURL(blob);
  const win = window.open(url, "_blank", "noopener,noreferrer");
  if (!win) {
    downloadBlob(blob, "ghosttrace_report.pdf");
  } else {
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }
}

export function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data ?? {}, null, 2)], { type: "application/json" });
  downloadBlob(blob, filename);
}

export function normalizeLevel(value) {
  const v = String(value || "").toLowerCase();
  if (["critical", "high", "medium", "low", "clean"].includes(v)) return v;
  if (v === "suspicious") return "medium";
  if (v === "safe") return "clean";
  return "medium";
}

export function severityFromText(text = "") {
  const t = String(text).toLowerCase();
  if (/(critical|rce|credential|exfil|malicious|phishing|backdoor|injection|malware|root|c2)/.test(t)) return "critical";
  if (/(high|suspicious|obfuscat|expired|missing|brute force)/.test(t)) return "high";
  if (/(medium|warning|warn|anomaly)/.test(t)) return "medium";
  return "low";
}

export function mapHistoryItem(doc, type) {
  const result = doc?.result || {};
  const risk = Number(doc?.risk_score ?? result?.risk?.score ?? result?.risk_score ?? 0);
  const level = normalizeLevel(doc?.severity ?? result?.risk?.severity ?? result?.threat_level);
  const iocs = result?.iocs || {};
  const iocCount = Array.isArray(iocs)
    ? iocs.length
    : Object.values(iocs).reduce((acc, arr) => acc + ((arr && arr.length) || 0), 0);
  const findings = Array.isArray(result?.suspicious_strings)
    ? result.suspicious_strings.length
    : Array.isArray(result?.findings)
      ? result.findings.length
      : 0;
  return {
    id: doc?.id || `${type}-${Math.random()}`,
    type,
    name: doc?.filename || doc?.url || doc?.target || result?.filename || result?.input_url || result?.target || `${type} scan`,
    level,
    risk,
    date: doc?.created_at ? new Date(doc.created_at).toLocaleString() : "-",
    findings,
    iocs: iocCount,
    ts: doc?.created_at ? new Date(doc.created_at).getTime() : 0,
  };
}

/**
 * mapFileResult — Converts UnifiedInvestigationResult (from /api/analyze-file)
 * into the shape that FileScanner.jsx expects.
 */
export function mapFileResult(data, fallback = {}) {
  if (!data) return fallback;

  // raw_artifacts holds hashes, entropy, yara_matches, file_type
  const raw = data.raw_artifacts || {};
  const hashes = raw.hashes || {};
  const yaraMatches = raw.yara_matches || [];
  const fileType = raw.file_type || data.type || "Unknown";
  const entropy = Number(raw.entropy ?? 0);

  // Flat IOC list [{type, value}] from unified model
  const flatIocs = Array.isArray(data.iocs) ? data.iocs : [];

  // Reconstruct the dict-style iocs the FileScanner display expects
  const iocDict = {};
  for (const ioc of flatIocs) {
    const key = String(ioc.type || "other") + "s";
    if (!iocDict[key]) iocDict[key] = [];
    iocDict[key].push(ioc.value);
  }

  // suspicious strings — we derive from iocs of type "string" or from raw
  const suspiciousStrings = (raw.suspicious_strings || []).map(v => ({ v, sus: true }));

  return {
    filename: data.target || fallback.filename || "unknown",
    type: fileType,
    size: raw.file_size ? `${Math.round(raw.file_size / 1024)} KB` : (fallback.size || "Unknown"),
    md5: hashes.md5 || fallback.md5 || "",
    sha1: hashes.sha1 || fallback.sha1 || "",
    sha256: hashes.sha256 || fallback.sha256 || "",
    entropy,
    packed: entropy > 7.0,
    signed: false,
    vt_ratio: raw.vt_ratio || fallback.vt_ratio || "N/A",
    sections: raw.sections || fallback.sections || [],
    imports: raw.imports || fallback.imports || [],
    yara: yaraMatches,
    strings: suspiciousStrings.length ? suspiciousStrings : (fallback.strings || []),
    iocs: iocDict,
    risk: Number(data.risk_score ?? fallback.risk ?? 0),
    level: String(data.severity || "low").toUpperCase(),
    confidence: Number(data.confidence ?? 0),
    mitre_mapping: data.mitre_mapping || [],
    ai: data.ai_explanation || fallback.ai || "No AI explanation available.",
    timeline: data.timeline || [],
    recommendations: data.recommendations || [],
  };
}

/**
 * mapUrlResult — Converts UnifiedInvestigationResult (from /api/analyze-url)
 * into the shape that URLScanner.jsx expects.
 */
export function mapUrlResult(data, scanUrl) {
  if (!data || !data.risk_score === undefined) {
    // Minimal safe fallback if called with empty data for pre-scan state
    return {
      url: scanUrl || "",
      ip: "N/A", country: "N/A", isp: "N/A", domain_age: "N/A", registrar: "N/A",
      ssl: { valid: false, issuer: "Unknown", expiry: "Unknown" },
      redirects: [scanUrl || "N/A"], tech: [], rep: { vt: "N/A", urlscan: "N/A", abuseipdb: "N/A", phishtank: "N/A" },
      checks: [], injections: [], vulns: [], health: { total: 0, ssl: 0, malware: 0, vulns: 0, rep: 0, content: 0 },
      content: { login_form: false, pass_field: false, form_action: "", hidden_iframes: 0, obfuscated_js: false, ext_scripts: [] },
      risk: 0, level: "low", iocs: {}, url_timeline: [], ai: "", mitre_mapping: [],
    };
  }

  // Unified model top-level fields
  const risk = Number(data.risk_score ?? 0);
  const level = normalizeLevel(data.severity);
  const confidence = Number(data.confidence ?? 50);

  // raw_artifacts contains page_artifacts, ssl_info, domain, ip_reputation, urlscan
  const raw = data.raw_artifacts || {};
  const page = raw.page_artifacts || {};
  const sslInfo = raw.ssl_info || {};
  const ipRep = String(raw.ip_reputation || "");
  const urlscanResult = raw.urlscan || {};
  const domain = raw.domain || "";

  // Derive IP from ip_reputation text or urlscan
  const ipMatch = ipRep.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  const resolvedIp = ipMatch ? ipMatch[0] : "N/A";

  // AbuseIPDB score from ip_rep string
  const abuseMatch = ipRep.match(/score\s+(\d+)\/100/i);
  const abuseScore = abuseMatch ? Number(abuseMatch[1]) : (ipRep.includes("AbuseIPDB") ? "Checked" : "N/A");

  // VirusTotal score from urlscan
  const vtScore = urlscanResult.score ?? "N/A";

  // Flat IOC list → dict by type
  const flatIocs = Array.isArray(data.iocs) ? data.iocs : [];
  const iocDict = { ips: [], domains: [], urls: [], emails: [], hashes: [], reg_keys: [], commands: [], cves: [] };
  for (const ioc of flatIocs) {
    const t = String(ioc.type || "").toLowerCase();
    if (t === "ip")       iocDict.ips.push(ioc.value);
    else if (t === "domain") iocDict.domains.push(ioc.value);
    else if (t === "url")   iocDict.urls.push(ioc.value);
    else if (t === "email") iocDict.emails.push(ioc.value);
    else if (t === "hash")  iocDict.hashes.push(ioc.value);
    else if (t === "command") iocDict.commands.push(ioc.value);
    else if (t === "cve")   iocDict.cves.push(ioc.value);
    else if (t === "reg_key") iocDict.reg_keys.push(ioc.value);
    else if (t === "script") iocDict.urls.push(ioc.value); // scripts go to URLs
  }

  // Security checks — build from known risk signals
  const checks = [
    { n: "HTTPS Protocol",        v: (scanUrl || data.target || "").startsWith("https://") ? "Enforced" : "Not enforced", ok: (scanUrl || data.target || "").startsWith("https://") },
    { n: "Risk Score",            v: `${risk}/100`, ok: risk < 35 },
    { n: "SSL Certificate",       v: sslInfo.status || "Unknown", ok: sslInfo.has_tls === true },
    { n: "SSL Expiry",            v: sslInfo.not_after || "Unknown", ok: (sslInfo.days_to_expiry ?? 99) > 14 },
    { n: "Suspicious Behaviors",  v: String(data.confidence ?? 0) + "% confidence threat", ok: risk < 35 },
    { n: "Hidden IFrames",        v: `${page.hidden_iframe_count ?? 0} detected`, ok: (page.hidden_iframe_count ?? 0) === 0 },
    { n: "Page Scripts",          v: `${page.script_count ?? 0} scripts`, ok: (page.script_count ?? 0) < 12 },
    { n: "Suspicious Forms",      v: `${page.suspicious_form_count ?? 0} detected`, ok: (page.suspicious_form_count ?? 0) === 0 },
  ];

  // Injections from timeline + page artifacts
  const injections = [];
  if ((page.hidden_iframe_count ?? 0) > 0) {
    injections.push({ sev: "critical", icon: "🪟", title: "Hidden IFrame Injection", detail: `${page.hidden_iframe_count} zero-size or display:none iframes detected. Common drive-by download vector.` });
  }
  if (page.suspicious_script_patterns?.length > 0) {
    injections.push({ sev: "critical", icon: "📜", title: "Obfuscated JavaScript Detected", detail: `Script patterns: ${page.suspicious_script_patterns.join(", ")}. Possible credential harvesting or cryptomining.` });
  }
  if ((page.suspicious_form_count ?? 0) > 0) {
    injections.push({ sev: "critical", icon: "💉", title: "Credential Harvesting Form", detail: "Login form detected posting over insecure channel or to suspicious endpoint." });
  }
  if (injections.length === 0) {
    injections.push({ sev: "info", icon: "✅", title: "No Direct Injection Pattern Identified", detail: "No active malicious injection behavior was confirmed from current page artifact scan." });
  }

  // Vulns from timeline entries tagged as vulnerabilities
  const vulns = (data.timeline || [])
    .filter(t => t.stage === "Vulnerability" || t.sev === "high" || t.sev === "critical")
    .slice(0, 5)
    .map((t, i) => ({
      sev: t.sev || "medium",
      name: t.stage || `Finding ${i + 1}`,
      cve: "CWE-693",
      evidence: t.details || "",
      fix: "Apply defensive hardening. Update affected components.",
    }));

  // Health breakdown
  const hb = raw.health_breakdown || data.health_breakdown || {};
  const health = {
    total: Math.max(0, 100 - risk),
    ssl:    Number(hb.ssl    ?? (sslInfo.has_tls ? 20 : 0)),
    malware: Number(hb.malware ?? Math.max(0, 30 - (injections.filter(i => i.sev === "critical").length * 10))),
    vulns:  Number(hb.vulnerability ?? Math.max(0, 20 - (vulns.length * 5))),
    rep:    Number(hb.reputation ?? (risk > 60 ? 0 : 15)),
    content: Number(hb.content  ?? (page.suspicious_form_count ? 0 : 15)),
  };

  // Timeline mapping
  const url_timeline = (data.timeline || []).map((t, i) => ({
    t: `T+${i}`,
    e: t.stage || `Step ${i + 1}`,
    d: t.details || "",
    sev: normalizeLevel(t.sev || "low"),
  }));

  return {
    url: data.target || scanUrl || "",
    ip: resolvedIp,
    country: raw.country || "N/A",
    isp: raw.isp || "N/A",
    domain_age: raw.domain_age || "N/A",
    registrar: raw.registrar || "N/A",
    ssl: {
      valid: Boolean(sslInfo.has_tls),
      issuer: sslInfo.issuer || "Unknown",
      expiry: sslInfo.not_after || "Unknown",
    },
    redirects: [data.target || scanUrl || "N/A"],
    tech: page.external_script_samples?.slice(0, 4) || [],
    rep: {
      vt: vtScore,
      urlscan: urlscanResult.verdict === true ? "Malicious" : urlscanResult.verdict === false ? "No malicious verdict" : "Unavailable",
      abuseipdb: abuseScore,
      phishtank: raw.phishtank_in_database ? "Confirmed phishing" : "Not listed",
    },
    checks,
    injections,
    vulns,
    health,
    content: {
      login_form: (page.suspicious_form_count ?? 0) > 0,
      pass_field: (page.suspicious_form_count ?? 0) > 0,
      form_action: page.suspicious_form_count ? "Detected — check via manual inspection" : "N/A",
      hidden_iframes: page.hidden_iframe_count ?? 0,
      obfuscated_js: (page.suspicious_script_patterns?.length ?? 0) > 0,
      ext_scripts: page.external_script_samples || [],
    },
    risk,
    level,
    confidence,
    iocs: iocDict,
    url_timeline,
    ai: data.ai_explanation || "No AI explanation available.",
    mitre_mapping: data.mitre_mapping || [],
    recommendations: data.recommendations || [],
  };
}

/**
 * mapLogResult — Converts UnifiedInvestigationResult (from /api/analyze-log)
 * into the shape that LogAnalyzer.jsx expects.
 */
export function mapLogResult(data, scanText = "") {
  if (!data) return D_LOG;

  const raw = data.raw_artifacts || {};
  const behaviorPatterns = raw.behavior_patterns || [];
  const ipMatches = raw.ip_matches || [];

  const flatIocs = Array.isArray(data.iocs) ? data.iocs : [];
  const iocDict = { ips: [], domains: [], urls: [], commands: [], hashes: [], emails: [], reg_keys: [], cves: [] };
  for (const ioc of flatIocs) {
    const t = String(ioc.type || "").toLowerCase();
    if (t === "ip") iocDict.ips.push(ioc.value);
    else if (t === "domain") iocDict.domains.push(ioc.value);
    else if (t === "command") iocDict.commands.push(ioc.value);
    else if (t === "url") iocDict.urls.push(ioc.value);
  }

  const timeline = (data.timeline || []).map((ev, i) => ({
    t: ev.stage ? `Stage ${i + 1}` : `T+${i}`,
    e: ev.stage || ev.details || `Event ${i + 1}`,
    d: ev.details || "",
    sev: normalizeLevel(ev.sev || "medium"),
  }));

  const lines = scanText ? scanText.split(/\r?\n/).filter(Boolean).length : 0;
  const suspicious = behaviorPatterns.length;

  return {
    ...D_LOG,
    lines: lines || D_LOG.lines,
    suspicious,
    critical: String(data.severity || "").toLowerCase() === "critical" ? Math.max(1, suspicious) : Math.min(suspicious, 2),
    anomalies: suspicious,
    risk: Number(data.risk_score ?? D_LOG.risk),
    level: String(data.severity || "high").toUpperCase(),
    confidence: Number(data.confidence ?? 0),
    iocs: iocDict,
    ai: data.ai_explanation || D_LOG.ai,
    timeline: timeline.length ? timeline : D_LOG.timeline,
    recommendations: data.recommendations || [],
    mitre_mapping: data.mitre_mapping || [],
    behavior_patterns: behaviorPatterns,
  };
}

export function useScan(steps) {
  const [phase, setPhase] = useState("idle");
  const [cur, setCur] = useState(-1);
  const [done, setDone] = useState([]);
  const start = useCallback(() => {
    setPhase("scanning"); setCur(0); setDone([]);
    let i = 0;
    const run = () => {
      if (i >= steps.length) { setPhase("done"); return; }
      setCur(i);
      setTimeout(() => { const idx = i; setDone(p => [...p, idx]); i++; run(); }, steps[i].dur);
    };
    run();
  }, [steps]);
  const reset = useCallback(() => { setPhase("idle"); setCur(-1); setDone([]); }, []);
  return { phase, cur, done, start, reset };
}
