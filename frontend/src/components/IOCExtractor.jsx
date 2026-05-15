import React, { useState, useCallback } from "react";
import { Badge, IOCPanel } from "./SOCLibrary";
import { DEMO_IOC_TEXT } from "./SOCConstants";

export function IOCExtractor({ onScanTrigger }) {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const extract = useCallback(src => {
    const t = src || text;
    if (!t.trim()) return;
    const ips   = [...new Set(t.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [])];
    const domains = [...new Set((t.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|io|co|info|biz|xyz|online|su|cc|pw)\b/gi) || []).filter(d => !d.match(/^\d/) && !ips.some(ip => d === ip)))];
    const urls  = [...new Set(t.match(/https?:\/\/[^\s"'<>\]]+/gi) || [])];
    const emails= [...new Set(t.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
    const hashes= [...new Set(t.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g) || [])];
    const reg_keys = [...new Set(t.match(/HK(?:LM|CU|CR|U|CC)\\[^\s"'\n]+/gi) || [])];
    const commands = [...new Set((t.match(/(?:cmd\.exe|powershell|bash|wget|curl|python|nc|ncat)\s+[^\n]{5,}/gi) || []).map(c => c.slice(0, 80)))];
    const cves  = [...new Set(t.match(/CVE-\d{4}-\d{4,7}/gi) || [])];
    setResult({ ips, domains, urls, emails, hashes, reg_keys, commands, cves });
  }, [text]);

  const total = result ? Object.values(result).reduce((a, v) => a + v.length, 0) : 0;

  const doExport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type:"application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "ghosttrace_iocs.json"; a.click();
  };

  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🔗 IOC Extractor</div>
        <div className="txt-sec txt-sm">Extract all Indicators of Compromise from logs, reports, emails, threat intel, or raw text</div>
      </div>

      <div className="g2">
        <div>
          <div className="card mb14">
            <div className="card-hd"><span className="card-title">📝 Input Text</span></div>
            <div className="card-body">
              <textarea className="inp textarea w100 mb12" style={{ height:230, fontSize:11, lineHeight:1.7 }} placeholder="Paste log entries, incident reports, email headers, threat intel feeds, or any raw text containing IOCs…" value={text} onChange={e => setText(e.target.value)} />
              <div className="fac gap8">
                <button className="btn btn-primary" onClick={() => extract(text)} disabled={!text.trim()}>⚡ Extract IOCs</button>
                <button className="btn btn-sec" onClick={() => { setText(DEMO_IOC_TEXT); extract(DEMO_IOC_TEXT); }}>Load Demo</button>
                <button className="btn btn-ghost" onClick={() => { setText(""); setResult(null); }}>Clear</button>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">🔎 Extraction Types</span></div>
            <div className="card-body" style={{ padding:"12px 18px" }}>
              {[["🔌","IP Addresses","IPv4 — public and private"],
                ["🌐","Domains","All major TLDs (.com .ru .io etc)"],
                ["🔗","URLs","http and https endpoints"],
                ["✉","Emails","Any valid email format"],
                ["🔐","File Hashes","MD5 (32) · SHA1 (40) · SHA256 (64)"],
                ["⚙","Registry Keys","HKLM, HKCU, HKCR full paths"],
                ["💻","Shell Commands","cmd.exe, powershell, bash, curl, wget"],
                ["⚠","CVEs / CWEs","CVE-YYYY-NNNNN format"],
              ].map(([ic, n, d]) => (
                <div key={n} className="ck-row">
                  <div className="ck-ic">{ic}</div>
                  <div className="ck-lbl">{n}</div>
                  <div className="ck-val txt-muted">{d}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div>
          {result ? (
            <>
              <div className="fjsb mb12">
                <div className="fac gap8"><span style={{ fontSize:15, fontWeight:700 }}>Results</span><Badge level="info">{total} IOCs Found</Badge></div>
                <div className="fac gap8">
                  <button className="btn btn-ghost btn-sm" onClick={doExport}>⬇ Export JSON</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => { navigator.clipboard?.writeText(JSON.stringify(result, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 2000); }}>
                    {copied ? "✓ Copied" : "Copy"}
                  </button>
                </div>
              </div>
              <div className="card mb14">
                <div className="card-body"><IOCPanel iocs={result} /></div>
              </div>
              {total > 0 && (
                <div className="card">
                  <div className="card-hd"><span className="card-title">📊 IOC Summary</span></div>
                  <div className="card-body" style={{ padding:0 }}>
                    <table className="tbl">
                      <thead><tr><th>Type</th><th>Count</th><th>Status</th></tr></thead>
                      <tbody>
                        {[["IPs","ips","ioc-ip"],["Domains","domains","ioc-domain"],["URLs","urls","ioc-url"],["Emails","emails","ioc-email"],["Hashes","hashes","ioc-hash"],["Reg Keys","reg_keys","ioc-reg"],["Commands","commands","ioc-cmd"],["CVEs","cves","ioc-cve"]].map(([lbl, key, cls]) =>
                          (result[key]?.length > 0) && (
                            <tr key={key}>
                              <td className="fac gap8"><Badge level={key}>{lbl}</Badge></td>
                              <td className="mono txt-xs">{result[key].length}</td>
                              <td><span className="live-dot" /> <span className="mono txt-xs txt-muted">Extracted</span></td>
                            </tr>
                          )
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="empty-state" style={{ height:400 }}>
              <div className="empty-icon">⛓</div>
              <div className="empty-title">Ready for extraction</div>
              <div className="empty-sub">Paste your forensic evidence on the left and click extract to identify all technical indicators.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
