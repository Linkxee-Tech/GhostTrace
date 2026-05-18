import React, { useState } from "react";
import { Badge, Pbar, RiskGauge, MITREGrid, IOCTable, ForensicTimeline } from "./SOCLibrary";
import { D_FILE, D_URL, D_LOG, DEMO_LOGS } from "./SOCConstants";
import { apiBlob, downloadBlob } from "./SOCUtils";

export function Walkthrough({ setView }) {
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scannedResult, setScannedResult] = useState(null);

  const startSimulatedScan = (callback) => {
    setSubmitting(true);
    setScanProgress(0);
    let current = 0;
    const interval = setInterval(() => {
      current += 10;
      setScanProgress(current);
      if (current >= 100) {
        clearInterval(interval);
        setSubmitting(false);
        callback();
      }
    }, 150);
  };

  const downloadDemoPdf = async () => {
    try {
      const blob = await apiBlob("/api/reports/preview-pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "invoice_update_Q4.exe",
          report_type: "file",
          severity: "critical",
          target: "invoice_update_Q4.exe",
          result_summary: "CRITICAL Trojan Dropper / Credential Harvester (Emotet Campaign). Full kill chain reconstructed.",
          created_at: new Date().toISOString(),
        }),
      });
      downloadBlob(blob, "ghosttrace_incident_report.pdf");
    } catch (e) {
      console.error(e);
      alert("Failed to download PDF report. Ensure backend is running!");
    }
  };

  return (
    <div className="view">
      <div className="fjsb mb20">
        <div>
          <div style={{ fontSize: 22, fontWeight: 800, marginBottom: 5 }}>🎓 Interactive Analyst Walkthrough</div>
          <div className="txt-sec txt-sm">Learn how to investigate, reconstruct, and report real cyber incidents in 5 steps</div>
        </div>
        <Badge level="purple">SOC Tier-2 Playbook</Badge>
      </div>

      {/* Playbook Progress Steps Bar */}
      <div className="card mb20" style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", position: "relative" }}>
          <div style={{ position: "absolute", left: "10%", right: "10%", top: "14px", height: "2px", background: "rgba(255,255,255,.05)", zIndex: 1 }} />
          <div style={{ position: "absolute", left: "10%", width: `${(step - 1) * 20}%`, top: "14px", height: "2px", background: "var(--cyan)", zIndex: 1, transition: "width .3s ease" }} />
          {[
            { n: 1, lbl: "Triage Alert" },
            { n: 2, lbl: "File Forensics" },
            { n: 3, lbl: "IP/URL Correlation" },
            { n: 4, lbl: "Log Timeline" },
            { n: 5, lbl: "Forensic Report" }
          ].map((s) => (
            <div key={s.n} style={{ zIndex: 2, display: "flex", flexDirection: "column", alignItems: "center", cursor: s.n <= step ? "pointer" : "not-allowed" }} onClick={() => s.n <= step && setStep(s.n)}>
              <div style={{
                width: 30, height: 30, borderRadius: "50%",
                background: s.n < step ? "var(--green)" : s.n === step ? "var(--cyan)" : "#161b22",
                border: `1.5px solid ${s.n <= step ? "var(--cyan)" : "rgba(255,255,255,.1)"}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontWeight: 700, fontSize: 12, color: s.n <= step ? "#0a0f1d" : "var(--t3)",
                boxShadow: s.n === step ? "0 0 10px var(--cyan)" : "none",
                transition: "all .3s ease"
              }}>
                {s.n < step ? "✓" : s.n}
              </div>
              <span className="mono" style={{ fontSize: 9, marginTop: 6, fontWeight: s.n === step ? "800" : "500", color: s.n === step ? "var(--cyan)" : "var(--t3)" }}>{s.lbl}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── STEP 1: TRIAGE ALERT ── */}
      {step === 1 && (
        <div style={{ animation: "fadeUp .3s ease" }}>
          <div className="card mb16">
            <div className="card-hd">
              <span className="card-title">🚨 Step 1: Firewall Telemetry Triage</span>
              <Badge level="critical">CRITICAL ALERT</Badge>
            </div>
            <div className="card-body">
              <p style={{ lineHeight: 1.6, marginBottom: 12 }}>
                At <strong>02:14:33 UTC</strong>, the intrusion detection system (IDS) logged a suspicious outbound connection from internal host <code>10.0.0.5</code>.
                A highly obfuscated binary was downloaded from an external IP address.
              </p>
              <div className="err-box mb16">
                <strong>Event Log:</strong><br />
                <code>[IDS] OUTBOUND TCP 10.0.0.5:54910 -> 185.220.101.47:80 [GET /payload.exe] -> bytes_written: 2,412,201 [invoice_update_Q4.exe]</code>
              </div>
              <div className="warn-box">
                <strong>💡 Analyst Insight:</strong> Cyber adversaries frequently use social engineering to trick employees into downloading malicious executable invoices (e.g. <code>.exe</code> files disguised as PDFs or documents). Passive metadata analysis is your first line of defense.
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-body" style={{ textAlign: "center", padding: "30px 20px" }}>
              <div style={{ fontSize: 24, marginBottom: 10 }}>🔍 Step 2 Preview: Deconstruct File Internals</div>
              <p className="txt-sec mb16" style={{ maxWidth: 600, margin: "0 auto 16px" }}>
                Let's run a Deep Static Scan of the retrieved payload <code>invoice_update_Q4.exe</code> to check hashes, YARA hits, API imports, and packing status.
              </p>
              <button className="btn btn-primary" onClick={() => {
                startSimulatedScan(() => {
                  setStep(2);
                });
              }}>
                {submitting ? `Extracting Artifacts (${scanProgress}%)...` : "Perform Deep File Analysis →"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── STEP 2: FILE FORENSICS ── */}
      {step === 2 && (
        <div style={{ animation: "fadeUp .3s ease" }}>
          <div className="card mb16">
            <div className="card-hd">
              <span className="card-title">📁 Step 2: Portable Executable (PE) Forensics</span>
              <Badge level="critical">EMOTET TROJAN LOADER</Badge>
            </div>
            <div className="card-body">
              <RiskGauge score={D_FILE.risk} severity={D_FILE.level} confidence={94} label="Binary Threat Rating" />
              <div style={{ marginTop: 20 }}>
                <p style={{ lineHeight: 1.6, marginBottom: 12 }}>
                  Static analysis of the binary reveals extreme malicious markers. The file's text section (.text) and resource section (.rsrc) possess section entropy of <strong>7.91</strong> and <strong>7.88</strong>, indicating runtime packing (likely UPX) to evade signature scanners.
                </p>
                <div className="feat-grid mb16">
                  <div className="feat-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 11, color: "var(--t3)", marginBottom: 4 }}>YARA RULES HIT</div>
                    <div style={{ color: "var(--red)", fontWeight: 700, fontSize: 13 }}>Trojan.Win32.Emotet.ABCD</div>
                    <div style={{ fontSize: 10, color: "var(--t3)" }}>Known malware signature matched</div>
                  </div>
                  <div className="feat-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 11, color: "var(--t3)", marginBottom: 4 }}>INJECTION CAPABILITY</div>
                    <div style={{ color: "var(--amber)", fontWeight: 700, fontSize: 13 }}>Process Injection Triad</div>
                    <div style={{ fontSize: 10, color: "var(--t3)" }}>CreateRemoteThread + VirtualAllocEx</div>
                  </div>
                  <div className="feat-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 11, color: "var(--t3)", marginBottom: 4 }}>VIRUSTOTAL REPUTATION</div>
                    <div style={{ color: "var(--red)", fontWeight: 700, fontSize: 13 }}>61 / 72 Engines Flagged</div>
                    <div style={{ fontSize: 10, color: "var(--t3)" }}>Unsigned executable database hit</div>
                  </div>
                </div>
                <div className="warn-box mb16">
                  <strong>🚨 Crucial Findings:</strong> Plaintext string extraction recovered a hardcoded IP <code>http://185.220.101.47/payload.bin</code>. This is the Command & Control (C2) endpoint!
                </div>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-body" style={{ textAlign: "center", padding: "30px 20px" }}>
              <div style={{ fontSize: 22, marginBottom: 10 }}>🌐 Step 3 Preview: Correlate Infrastructure Reputation</div>
              <p className="txt-sec mb16" style={{ maxWidth: 600, margin: "0 auto 16px" }}>
                Now we must analyze the reputation of the extracted C2 IP <code>185.220.101.47</code> and the domain <code>secure-paypa1.com</code> to verify passive hosting risk.
              </p>
              <button className="btn btn-primary" onClick={() => {
                startSimulatedScan(() => {
                  setStep(3);
                });
              }}>
                {submitting ? `Correlating Indicators (${scanProgress}%)...` : "Run Passive Domain & IP Scan →"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── STEP 3: IP/URL CORRELATION ── */}
      {step === 3 && (
        <div style={{ animation: "fadeUp .3s ease" }}>
          <div className="card mb16">
            <div className="card-hd">
              <span className="card-title">🌐 Step 3: Infrastructure Intelligence</span>
              <Badge level="critical">TYPOSQUATTING & BULLETPROOF HOSTING</Badge>
            </div>
            <div className="card-body">
              <RiskGauge score={D_URL.risk} severity={D_URL.level} confidence={88} label="Network Infrastructure Risk" />
              <div style={{ marginTop: 20 }}>
                <p style={{ lineHeight: 1.6, marginBottom: 12 }}>
                  Cross-referencing the extracted IP and associated phishing domains against our global threat intelligence aggregators confirms active malicious operations.
                </p>
                <table className="tbl mb16">
                  <thead>
                    <tr><th>Indicator</th><th>Context Findings</th><th>Threat Severity</th></tr>
                  </thead>
                  <tbody>
                    <tr><td><code>185.220.101.47</code></td><td>Frantech Solutions (Bulletproof Hosting Provider)</td><td><Badge level="critical">CRITICAL (94 Reports)</Badge></td></tr>
                    <tr><td><code>secure-paypa1.com</code></td><td>Typosquatting brand impersonation. Registered 3 days ago.</td><td><Badge level="critical">PHISHING</Badge></td></tr>
                    <tr><td>SSL Certificate</td><td>Self-signed issuer, expired in 2022. No CSP headers.</td><td><Badge level="high">HIGH RISK</Badge></td></tr>
                    <tr><td>DOM Analysis</td><td>Hidden forms and evaluations exfiltrating to bare IP.</td><td><Badge level="critical">DATA EXFIL</Badge></td></tr>
                  </tbody>
                </table>
                <div className="ok-box">
                  <strong>💡 Defensive Tip:</strong> Block <code>185.220.101.47</code> on the enterprise perimeter firewall and isolate host <code>10.0.0.5</code> immediately to prevent malware exfiltration beacons.
                </div>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-body" style={{ textAlign: "center", padding: "30px 20px" }}>
              <div style={{ fontSize: 22, marginBottom: 10 }}>📋 Step 4 Preview: Reconstruct Log Events & MITRE Chain</div>
              <p className="txt-sec mb16" style={{ maxWidth: 600, margin: "0 auto 16px" }}>
                Next, we will ingest host authentication logs to trace the attacker's actions once inside the host: from brute-forcing to privilege escalation.
              </p>
              <button className="btn btn-primary" onClick={() => {
                startSimulatedScan(() => {
                  setStep(4);
                });
              }}>
                {submitting ? `Mapping Attack Chain (${scanProgress}%)...` : "Perform Log Behavioral Analysis →"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── STEP 4: LOG TIMELINE ── */}
      {step === 4 && (
        <div style={{ animation: "fadeUp .3s ease" }}>
          <div className="card mb16">
            <div className="card-hd">
              <span className="card-title">📋 Step 4: Host Forensics & Attack Chain Reconstruction</span>
              <Badge level="high">INTRUSION DETECTED</Badge>
            </div>
            <div className="card-body">
              <p style={{ lineHeight: 1.6, marginBottom: 14 }}>
                Log ingestion reveals the attacker succeeded in brute-forcing the password, gaining interactive console access as <code>ubuntu</code>, escalating privileges to root via a <code>sudo</code> bypass, and establishing cron-based persistence!
              </p>

              <SecHd>MITRE ATT&CK Alignment</SecHd>
              <div className="feat-grid mb16">
                <div className="feat-card" style={{ padding: "10px 14px" }}>
                  <div className="mono txt-xs" style={{ color: "var(--cyan)", fontWeight: 700 }}>T1566.001 - Phishing Attachment</div>
                  <div style={{ fontSize: 11, color: "var(--t2)", marginTop: 4 }}>Initial compromise vector (invoice email)</div>
                </div>
                <div className="feat-card" style={{ padding: "10px 14px" }}>
                  <div className="mono txt-xs" style={{ color: "var(--cyan)", fontWeight: 700 }}>T1110 - Brute Force</div>
                  <div style={{ fontSize: 11, color: "var(--t2)", marginTop: 4 }}>SSHD password storm from C2 IP</div>
                </div>
                <div className="feat-card" style={{ padding: "10px 14px" }}>
                  <div className="mono txt-xs" style={{ color: "var(--cyan)", fontWeight: 700 }}>T1078 - Valid Accounts</div>
                  <div style={{ fontSize: 11, color: "var(--t2)", marginTop: 4 }}>Successful SSH login accepted</div>
                </div>
                <div className="feat-card" style={{ padding: "10px 14px" }}>
                  <div className="mono txt-xs" style={{ color: "var(--cyan)", fontWeight: 700 }}>T1547.001 - Persistence Key</div>
                  <div style={{ fontSize: 11, color: "var(--t2)", marginTop: 4 }}>Cron script added to execute hourly beacons</div>
                </div>
              </div>

              <SecHd>Timeline of Attacker Actions</SecHd>
              <div className="tl-wrap">
                <div className="tl-event critical">
                  <div className="tl-time">02:14:33</div>
                  <div className="tl-card">
                    <div className="tl-title">SSH Brute Force Attack</div>
                    <div className="tl-body">894 failed logins from 185.220.101.47</div>
                  </div>
                </div>
                <div className="tl-event critical">
                  <div className="tl-time">02:22:11</div>
                  <div className="tl-card">
                    <div className="tl-title">Successful SSH Auth Accepted</div>
                    <div className="tl-body">Session established for user 'ubuntu'</div>
                  </div>
                </div>
                <div className="tl-event high">
                  <div className="tl-time">02:22:45</div>
                  <div className="tl-card">
                    <div className="tl-title">Privilege Escalation via Sudo</div>
                    <div className="tl-body"><code>sudo -i</code> executed for root terminal</div>
                  </div>
                </div>
                <div className="tl-event high">
                  <div className="tl-time">02:23:01</div>
                  <div className="tl-card">
                    <div className="tl-title">Persistence Cron Entry</div>
                    <div className="tl-body">Hourly curl script configured to beacon external C2</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-body" style={{ textAlign: "center", padding: "30px 20px" }}>
              <div style={{ fontSize: 22, marginBottom: 10 }}>📑 Step 5 Preview: Sign-off & Export PDF Forensic Report</div>
              <p className="txt-sec mb16" style={{ maxWidth: 600, margin: "0 auto 16px" }}>
                We have verified the full attack chain. Let's package these multi-source findings into a formal PDF report to complete the investigation.
              </p>
              <button className="btn btn-primary" onClick={() => {
                startSimulatedScan(() => {
                  setStep(5);
                });
              }}>
                {submitting ? `Compiling Report (${scanProgress}%)...` : "Compile & Finalize Case →"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── STEP 5: FORENSIC REPORT ── */}
      {step === 5 && (
        <div style={{ animation: "fadeUp .3s ease" }}>
          <div className="card mb16">
            <div className="card-hd">
              <span className="card-title">📑 Step 5: Incident Resolved & Final Sign-Off</span>
              <Badge level="clean">MITRE MAPPED & COMPILED</Badge>
            </div>
            <div className="card-body" style={{ textAlign: "center", padding: "40px 20px" }}>
              <div style={{ fontSize: 48, marginBottom: 16 }}>🏆</div>
              <div style={{ fontSize: 22, fontWeight: 800, marginBottom: 8, color: "var(--green)" }}>playbook Investigation Complete!</div>
              <p className="txt-sec mb24" style={{ maxWidth: 600, margin: "0 auto 24px", lineHeight: 1.7 }}>
                You have successfully Triaged the alert, performed Deep File forensics, analyzed domain reputation, parsed malicious logs, and reconstructed the full attack chain. This is exactly how GhostTrace empowers Security Operations Centers to operate with high-speed intelligence.
              </p>
              <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
                <button className="btn btn-primary btn-lg" onClick={downloadDemoPdf}>⬇ Download Forensic PDF Report</button>
                <button className="btn btn-sec btn-lg" onClick={() => setView("dashboard")}>🏠 Return to Dashboard</button>
                <button className="btn btn-ghost btn-lg" onClick={() => setStep(1)}>↩ Restart Walkthrough</button>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-hd"><span className="card-title">📖 Investigation Case Summary</span></div>
            <div className="card-body">
              <table className="tbl">
                <tbody>
                  <tr><td className="txt-muted" style={{ width: 140 }}>Case Reference</td><td className="mono" style={{ color: "var(--cyan)" }}>INC-2026-EMOTET</td></tr>
                  <tr><td className="txt-muted">Attacker Origin IP</td><td className="mono">185.220.101.47 (Frantech Bulletproof)</td></tr>
                  <tr><td className="txt-muted">Compromised Host</td><td className="mono">10.0.0.5 (Ubuntu Server-04)</td></tr>
                  <tr><td className="txt-muted">Primary Payload</td><td className="mono">invoice_update_Q4.exe (Trojan Loader)</td></tr>
                  <tr><td className="txt-muted">MITRE Tactics Resolved</td><td>Initial Access, Execution, Persistence, Privilege Escalation, Command & Control</td></tr>
                  <tr><td className="txt-muted">Remediation Status</td><td><span style={{ color: "var(--green)", fontWeight: 700 }}>✓ Host isolated · IP Blocked</span></td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SecHd({ children }) {
  return <div style={{ fontSize: 13, fontWeight: 700, color: "var(--t1)", borderBottom: "1px solid rgba(255,255,255,.05)", paddingBottom: 6, margin: "18px 0 10px" }}>{children}</div>;
}
