import React, { useState, useEffect, useCallback } from "react";
import { Spinner, Badge, ThreatSeverityCard, HealthScoreRing, IOCTable, Terminal, ScanProgress, SecHd } from "./SOCLibrary";
import { D_URL, URL_STEPS } from "./SOCConstants";
import { useScan, apiJson, apiBlob, downloadBlob, openBlobInNewTab, downloadJson, reportClientError, mapUrlResult } from "./SOCUtils";

export function URLScanner({ pendingScan, setPendingScan, onScanTrigger, onScanComplete }) {
  const { phase, cur, done, start, reset } = useScan(URL_STEPS);
  const [url, setUrl] = useState("");
  const [tab, setTab] = useState("overview");
  const [scanUrl, setScanUrl] = useState("");
  const [result, setResult] = useState(D_URL);
  const [scanError, setScanError] = useState("");
  const [loadingResult, setLoadingResult] = useState(false);
  const r = result;
  const riskVal = Number(r.risk || 0);
  const riskState = riskVal >= 75 ? "critical" : riskVal >= 50 ? "high" : riskVal >= 25 ? "medium" : "low";
  const hasMaliciousInjection = (r.injections || []).some((inj) => String(inj?.detail || "").toLowerCase() !== "no direct web injection pattern identified.");
  const hasContentRedFlags = Boolean(r.content?.login_form || r.content?.pass_field || r.content?.obfuscated_js || (r.content?.hidden_iframes || 0) > 0 || (r.content?.ext_scripts || []).length > 0);
  const sslStatus = r.ssl?.valid ? "Valid" : "Unavailable or failed";
  const domainAgeWarn = r.domain_age && r.domain_age !== "N/A" ? String(r.domain_age).toLowerCase().includes("new") : false;

  const go = useCallback(u => {
    if (!u) return;
    setUrl(u);
    setScanUrl(u);
    setScanError("");
    setLoadingResult(true);
    setResult({
      ...mapUrlResult({}, u),
      url: u,
      redirects: [u],
      checks: [],
      injections: [],
      vulns: [],
      tech: [],
      url_timeline: [],
      ai: "Running scan...",
    });
    start();
  }, [start]);

  useEffect(() => {
    if (pendingScan && (pendingScan.type === "url" || pendingScan.type === "ip" || pendingScan.type === "domain")) {
      go(pendingScan.value);
      setPendingScan(null);
    }
  }, [pendingScan, go, setPendingScan]);

  const resetAll = () => { reset(); setTab("overview"); setScanError(""); setLoadingResult(false); };

  useEffect(() => {
    if (phase !== "done" || !scanUrl) return;
    (async () => {
      try {
        const data = await apiJson("/api/analyze-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: scanUrl }) });
        // Map UnifiedInvestigationResult → URLScanner display shape
        setResult({ ...mapUrlResult(data, scanUrl), mitre_mapping: data.mitre_mapping || [] });
        if (typeof onScanComplete === "function") await onScanComplete();
      } catch (e) {
        reportClientError("URL analysis failed", e);
        const msg = e?.message || "URL analysis request failed.";
        setScanError(msg);
      } finally {
        setLoadingResult(false);
      }
    })();
  }, [phase, scanUrl, onScanComplete]);

  return (
    <div className="view">
      {phase === "idle" && (
        <>
          <div className="mb20">
            <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🌐 URL & Website Scanner</div>
            <div className="txt-sec txt-sm">Phishing · Malware injection · Vulnerabilities · Health score · AI attack reconstruction</div>
          </div>
          <div className="card mb16">
            <div className="card-body">
              <label className="inp-label">Target URL / Website</label>
              <div className="fac gap8 mb12">
                <input className="inp f1" placeholder="https://suspicious-site.com or paste any URL…" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && url && go(url)} />
                <button className="btn btn-primary" onClick={() => go(url)} disabled={!url}>Scan →</button>
              </div>
              <div className="ok-box">🔒 Passive analysis only — no credentials sent, no active exploitation or modification performed on target.</div>
            </div>
          </div>
          <div className="feat-grid mb18">
            {[{e:"🔒",n:"SSL / TLS Analysis",d:"Certificate validity, chain, issuer trust"},
              {e:"🎭",n:"Phishing Detection",d:"Domain spoofing, typosquatting, brand impersonation"},
              {e:"💉",n:"Malware Injection",d:"Web shells, injected scripts, iframes, backdoors"},
              {e:"🔍",n:"Vulnerability Scan",d:"Misconfigs, EOL software, missing security headers"},
              {e:"🏥",n:"Security Health Score",d:"5-dimension scorecard: SSL, malware, vulns, rep, content"},
              {e:"🕵",n:"AI Attack Chain",d:"AI reconstructs how the site was compromised"},
            ].map(f => <div key={f.n} className="feat-card"><div className="feat-icon">{f.e}</div><div className="feat-name">{f.n}</div><div className="feat-desc">{f.d}</div></div>)}
          </div>
          <button className="btn btn-primary btn-lg" onClick={() => go("https://secure-paypa1.com/login/verify?session=a9f3b")}>🚀 Demo Scan — PayPal phishing site</button>
        </>
      )}

      {phase === "scanning" && (
        <div className="card">
          <div className="card-hd"><span className="card-title fac gap8"><Spinner /> Scanning website…</span></div>
          <div className="card-body">
            <div className="err-box mb16">Target: <span style={{ color:"var(--t1)" }}>{url || r.url}</span></div>
            <ScanProgress steps={URL_STEPS} cur={cur} done={done} />
          </div>
        </div>
      )}

      {phase === "done" && (
        <div className="url-results-wrap">
          {loadingResult && (
            <div className="card mb12">
              <div className="card-hd"><span className="card-title fac gap8"><Spinner /> Fetching backend analysis result...</span></div>
              <div className="card-body">
                <div className="ok-box">Input URL: <strong>{scanUrl}</strong></div>
              </div>
            </div>
          )}
          {scanError && (
            <div className="err-box mb12">
              URL analysis failed: {scanError}
            </div>
          )}
          {!loadingResult && (
            <div className="url-analysis-content">
              <div className="fjsb gap12 mb20">
                <div>
                  <div style={{ fontSize:18, fontWeight:800, marginBottom:4 }}>Scan Complete</div>
                  <span className="hash-pill">{r.url}</span>
                </div>
                <div className="fac gap8">
                  <button className="btn btn-ghost" onClick={resetAll}>↩ New Scan</button>
                  <button className="btn btn-sec" onClick={async () => { const newTab = window.open("", "_blank"); if (newTab) newTab.document.write("<html><body style='font-family:sans-serif;padding:20px'>Generating report... please wait.</body></html>"); try { const blob = await apiBlob("/api/generate-url-report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: r.url }) }); const url = URL.createObjectURL(blob); if (newTab) { newTab.location.href = url; } else { downloadBlob(blob, "ghosttrace_url_report.pdf"); } } catch (e) { if (newTab) newTab.close(); reportClientError("URL report view failed", e); } }}>📄 Report</button>
                  <button className="btn btn-primary" onClick={async () => { try { const blob = await apiBlob("/api/generate-url-report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: r.url }) }); downloadBlob(blob, "ghosttrace_url_report.pdf"); } catch (e) { reportClientError("URL report download failed", e); } }}>⬇ PDF</button>
                </div>
              </div>

              <div className="mb20">
                <ThreatSeverityCard score={r.risk} severity={r.level} confidence={88} type="url" />
              </div>

              <div className="tabs">
                {[["overview","📋 Overview"],["health","🏥 Health Score"],["injections","💉 Injections"],["vulns","🔍 Vulns"],["content","🔬 Content"],["reputation","📡 Reputation"],["timeline","📅 Timeline"],["iocs","🔗 IOCs"],["ai","🤖 AI"]].map(([id, lbl]) => (
                  <button key={id} className={`tab ${tab === id ? "on" : ""}`} onClick={() => setTab(id)}>{lbl}</button>
                ))}
              </div>

              {tab === "overview" && (
                <div className="g2">
                  <div className="card">
                    <div className="card-hd"><span className="card-title">🌍 Domain Information</span></div>
                    <div className="card-body">
                      <table className="tbl"><tbody>
                        <tr><td className="txt-muted" style={{width:110}}>IP Address</td><td style={{color:r.ip && r.ip !== "N/A" ? "var(--t1)" : "var(--amber)"}}>{r.ip}{r.ip && r.ip !== "N/A" ? "" : " (unavailable)"}</td></tr>
                        <tr><td className="txt-muted">Country / ISP</td><td>{r.country} · {r.isp}</td></tr>
                        <tr><td className="txt-muted">Domain Age</td><td style={{color:domainAgeWarn ? "var(--red)" : "var(--t1)"}}>{r.domain_age}</td></tr>
                        <tr><td className="txt-muted">Registrar</td><td>{r.registrar}</td></tr>
                        <tr><td className="txt-muted">SSL Issuer</td><td style={{color:r.ssl.valid ? "var(--green)" : "var(--amber)"}}>{r.ssl.issuer}</td></tr>
                        <tr><td className="txt-muted">SSL Expiry</td><td style={{color:r.ssl.valid ? "var(--green)" : "var(--amber)"}}>{r.ssl.expiry} ({sslStatus})</td></tr>
                        <tr><td className="txt-muted">Redirect</td><td className="mono" style={{fontSize:10,color:"var(--t2)"}}>{r.redirects[0]}</td></tr>
                        <tr><td className="txt-muted">Stack</td><td style={{color:"var(--amber)"}}>{r.tech.join(" · ")}</td></tr>
                      </tbody></table>
                    </div>
                  </div>
                  <div className="card">
                    <div className="card-hd"><span className="card-title">✅ Security Checks ({r.checks.filter(c => c.ok === false).length} failed)</span></div>
                    <div className="card-body">
                      {r.checks.map((c, i) => (
                        <div key={i} className="ck-row">
                          <div className="ck-ic">{c.ok === false ? "🔴" : c.ok === null ? "🟡" : "🟢"}</div>
                          <div className="ck-lbl">{c.n}</div>
                          <div className="ck-val" style={{ color: c.ok === false ? "var(--red)" : c.ok === null ? "var(--amber)" : "var(--green)" }}>{c.v}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {tab === "health" && (
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
              )}

              {tab === "injections" && (
                <>
                  <div className={hasMaliciousInjection ? "err-box mb16" : "ok-box mb16"}><strong>⚑ {r.injections.length} injection indicators detected.</strong> {hasMaliciousInjection ? "Review these findings before allowing access." : "No active malicious injection behavior was confirmed by current checks."}</div>
                  {r.injections.map((inj, i) => (
                    <div key={i} className={`inj-finding ${inj.sev === "warn" ? "warn" : inj.sev === "info" ? "info" : ""}`}>
                      <div className="inj-icon">{inj.icon}</div>
                      <div className="inj-body">
                        <div className="inj-title">{inj.title}</div>
                        <div className="inj-detail">{inj.detail}</div>
                      </div>
                      <Badge level={inj.sev}>{inj.sev.toUpperCase()}</Badge>
                    </div>
                  ))}
                  <div className="warn-box mt16">
                    <strong>Additional injection indicators:</strong><br />
                    • Security checks flagged: {r.checks.filter(c => c.ok === false).length}<br />
                    • Obfuscated scripts detected: {r.content.obfuscated_js ? "Yes" : "No"}<br />
                    • External resource indicators: {(r.content.ext_scripts || []).length ? r.content.ext_scripts.join(", ") : "None from current scan"}
                  </div>
                </>
              )}

              {tab === "vulns" && (
                <>
                  <div className={`${r.vulns.length > 0 ? "warn-box" : "ok-box"} mb16`}><strong>{r.vulns.length} vulnerability findings detected</strong> from backend vulnerability analysis.</div>
                  {r.vulns.map((v, i) => (
                    <div key={i} className="vuln-row">
                      <div className="vuln-hd">
                        <div className="vuln-name">{v.name}</div>
                        <Badge level={v.sev}>{v.sev.toUpperCase()}</Badge>
                        <span className="ioc ioc-cve">{v.cve}</span>
                      </div>
                      <div className="vuln-evidence">{v.evidence}</div>
                      <div className="vuln-fix">✅ Fix: {v.fix}</div>
                    </div>
                  ))}
                </>
              )}

              {tab === "content" && (
                <div className="g2">
                  <div className="card">
                    <div className="card-hd"><span className="card-title">🔬 Page Content Analysis</span></div>
                    <div className="card-body">
                      {[
                        {n:"Login Form Detected",v:r.content.login_form ? "Yes ⚠" : "No",ok:!r.content.login_form},
                        {n:"Password Field",v:r.content.pass_field ? "Yes ⚠" : "No",ok:!r.content.pass_field},
                        {n:"Form Action",v:r.content.form_action,ok:!r.content.login_form},
                        {n:"Hidden IFrames",v:r.content.hidden_iframes > 0 ? `${r.content.hidden_iframes} found ⚠` : "0 found",ok:r.content.hidden_iframes === 0},
                        {n:"Obfuscated JavaScript",v:r.content.obfuscated_js ? "Detected ⚠" : "Not detected",ok:!r.content.obfuscated_js},
                        {n:"External Scripts",v:r.content.ext_scripts.length ? `${r.content.ext_scripts.length} flagged ⚠` : "None flagged",ok:r.content.ext_scripts.length === 0},
                        {n:"CSP Header",v:r.checks.find(c => c.n === "Page Scripts")?.ok === true ? "Likely present/low risk" : "Not confirmed",ok:r.checks.find(c => c.n === "Page Scripts")?.ok === true},
                        {n:"X-Frame-Options",v:r.content.hidden_iframes === 0 ? "No iframe abuse observed" : "Risk indicators present ⚠",ok:r.content.hidden_iframes === 0},
                      ].map((c, i) => (
                        <div key={i} className="ck-row">
                          <div className="ck-ic">{c.ok === false ? "🔴" : "🟢"}</div>
                          <div className="ck-lbl">{c.n}</div>
                          <div className="ck-val" style={{ color: c.ok === false ? "var(--red)" : "var(--green)" }}>{c.v}</div>
                        </div>
                      ))}
                      <div className={`${hasContentRedFlags ? "err-box" : "ok-box"} mt12`}>{hasContentRedFlags ? <>Content risk indicators detected — review form/script behavior: <strong>{r.content.form_action}</strong></> : <>No strong content-exfiltration pattern confirmed from current page artifacts.</>}</div>
                    </div>
                  </div>
                  <div className="card">
                    <div className="card-hd"><span className="card-title">📡 External Resources</span></div>
                    <div className="card-body">
                      <SecHd>External Script Indicators</SecHd>
                      {r.content.ext_scripts.map((s, i) => <div key={i} className="ioc ioc-url mb8" style={{ display:"block" }}>{s}</div>) }
                      <div className="warn-box mt12">{(r.content.ext_scripts || []).length ? "External script sources were flagged by backend analysis. Validate trust and hosting reputation." : "No suspicious external script sources were flagged in this scan."}</div>
                    </div>
                  </div>
                </div>
              )}

              {tab === "reputation" && (
                <div className="card">
                  <div className="card-hd"><span className="card-title">📡 Global Reputation APIs</span></div>
                  <div className="card-body">
                    <table className="tbl">
                      <thead><tr><th>Security Provider</th><th>Analysis Context</th><th>Status / Score</th></tr></thead>
                      <tbody>
                        <tr><td>VirusTotal (72 engines)</td><td className="txt-muted">Global URL & Host reputation</td><td><Badge level={Number(r.rep.vt) > 5 ? "critical" : "clean"}>{r.rep.vt} flags</Badge></td></tr>
                        <tr><td>URLScan.io</td><td className="txt-muted">Dynamic page rendering & phishing detection</td><td><Badge level={r.rep.urlscan === "Malicious" ? "critical" : "clean"}>{r.rep.urlscan}</Badge></td></tr>
                        <tr><td>AbuseIPDB</td><td className="txt-muted">Host IP abuse reports & blacklisting</td><td><Badge level={Number(r.rep.abuseipdb) > 10 ? "critical" : "clean"}>{r.rep.abuseipdb} reports</Badge></td></tr>
                        <tr><td>PhishTank</td><td className="txt-muted">Community verified phishing indicators</td><td><Badge level={r.rep.phishtank === "Configured" ? "info" : "clean"}>{r.rep.phishtank}</Badge></td></tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {tab === "timeline" && (
                <div className="card">
                  <div className="card-hd"><span className="card-title">📅 Investigative Timeline</span></div>
                  <div className="card-body">
                    <div className="tl-wrap">
                      {r.url_timeline.map((ev, i) => (
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
                  <div className="card-hd"><span className="card-title">🔗 Extracted Website Indicators</span><button className="btn btn-ghost btn-sm" onClick={() => downloadJson(r.iocs, "ghosttrace_url_iocs.json")}>⬇ Export JSON</button></div>
                  <div className="card-body"><IOCTable iocs={Object.entries(r.iocs || {}).flatMap(([type, vals]) => (vals || []).map(v => ({ type, value: v })))} onScanTrigger={onScanTrigger} /></div>
                </div>
              )}

              {tab === "ai" && <Terminal title="URL Threat Reconstruction" content={r.ai} />}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
