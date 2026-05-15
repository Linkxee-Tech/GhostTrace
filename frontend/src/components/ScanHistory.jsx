import React, { useState, useMemo } from "react";
import { Badge, Pbar } from "./SOCLibrary";
import { HISTORY } from "./SOCConstants";
import { apiBlob, downloadBlob, downloadJson, reportClientError } from "./SOCUtils";

export function ScanHistory({ setView, historyItems = HISTORY }) {
  const [q, setQ] = useState("");
  const [fType, setFType] = useState("all");
  const [fLevel, setFLevel] = useState("all");
  const typeIcon = { file:"📁", url:"🌐", log:"📋", ioc:"🔗" };
  const lvlBg = { critical:"rgba(255,45,85,.1)", high:"rgba(255,170,0,.1)", medium:"rgba(59,130,246,.1)", low:"rgba(0,255,136,.08)", clean:"rgba(0,255,136,.08)" };

  const filtered = useMemo(() => historyItems.filter(s => {
    const mQ = !q || s.name.toLowerCase().includes(q.toLowerCase());
    const mT = fType === "all" || s.type === fType;
    const mL = fLevel === "all" || s.level === fLevel;
    return mQ && mT && mL;
  }), [q, fType, fLevel, historyItems]);

  const onView = (s) => {
    if (s.type === "file") setView("file-scan");
    else if (s.type === "url") setView("url-scan");
    else if (s.type === "log") setView("log-scan");
    else setView("ioc");
  };
  const onPdf = async (s) => {
    try {
      if (s.type === "url" && /^https?:\/\//i.test(String(s.name || ""))) {
        const blob = await apiBlob("/api/generate-url-report", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: s.name }),
        });
        downloadBlob(blob, "ghosttrace_url_report.pdf");
        return;
      }
      downloadJson(s, `ghosttrace_history_${s.type}_${String(s.id || "item")}.json`);
    } catch (e) { reportClientError("History report action failed", e); }
  };

  return (
    <div className="view">
      <div className="fjsb mb20">
        <div>
          <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>📊 Scan History</div>
          <div className="txt-sec txt-sm">All {historyItems.length} past scans — searchable and filterable</div>
        </div>
        <button className="btn btn-primary" onClick={() => setView("file-scan")}>+ New Scan</button>
      </div>

      <div className="fac gap10 mb16">
        <div className="search-bar f1">
          <span className="txt-muted" style={{ fontSize:14 }}>🔍</span>
          <input placeholder="Search by filename, URL, or target…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
        <select className="inp sel" style={{ width:130 }} value={fType} onChange={e => setFType(e.target.value)}>
          <option value="all">All Types</option>
          <option value="file">File</option>
          <option value="url">URL</option>
          <option value="log">Log</option>
          <option value="ioc">IOC</option>
        </select>
        <select className="inp sel" style={{ width:140 }} value={fLevel} onChange={e => setFLevel(e.target.value)}>
          <option value="all">All Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="clean">Clean</option>
        </select>
      </div>

      <div className="card">
        <div className="card-hd">
          <span className="card-title">🔎 Results</span>
          <span className="mono txt-xs txt-muted">{filtered.length} of {historyItems.length} scans</span>
        </div>
        <div style={{ padding:0 }}>
          <table className="tbl">
            <thead>
              <tr><th>Target</th><th>Type</th><th>Risk</th><th>Level</th><th>Findings</th><th>IOCs</th><th>Date</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {filtered.map((s, i) => (
                <tr key={i}>
                  <td>
                    <div className="fac gap8">
                      <div style={{ width:28, height:28, borderRadius:6, background:lvlBg[s.level], display:"flex", alignItems:"center", justifyContent:"center", fontSize:13, flexShrink:0 }}>{typeIcon[s.type]}</div>
                      <span style={{ color:"var(--t1)", fontWeight:600, maxWidth:200, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{s.name}</span>
                    </div>
                  </td>
                  <td><Badge level={s.type}>{s.type.toUpperCase()}</Badge></td>
                  <td>
                    <div className="fac gap6">
                      <span className="mono txt-xs" style={{ color: s.level === "critical" ? "var(--red)" : s.level === "high" ? "var(--amber)" : s.level === "medium" ? "var(--blue)" : "var(--green)" }}>{s.risk}</span>
                      <div style={{ width:44 }}><Pbar val={s.risk} color={s.level === "critical" || s.level === "high" ? "red" : "green"} /></div>
                    </div>
                  </td>
                  <td><Badge level={s.level}>{s.level}</Badge></td>
                  <td><span className="mono txt-xs" style={{ color: s.findings > 0 ? "var(--amber)" : "var(--t3)" }}>{s.findings}</span></td>
                  <td><span className="mono txt-xs" style={{ color: s.iocs > 0 ? "var(--cyan)" : "var(--t3)" }}>{s.iocs}</span></td>
                  <td className="mono txt-xs txt-muted tbl-nowrap">{s.date}</td>
                  <td>
                    <div className="fac gap6">
                      <button className="btn btn-ghost btn-sm" onClick={() => onView(s)}>View</button>
                      <button className="btn btn-ghost btn-sm" onClick={() => onPdf(s)}>⬇ PDF</button>
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={8}><div className="empty-state"><div className="empty-icon">🔍</div><div className="empty-title">No results</div><div className="empty-sub">No scans match your search or filters.</div></div></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
