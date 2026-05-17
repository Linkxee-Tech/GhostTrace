import React, { useEffect, useRef, useState } from "react";
import { NAV } from "./SOCConstants";

export function Sidebar({ view, setView, backendStatus }) {
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  // Live WebSocket connection for real-time alerts
  useEffect(() => {
    const connect = () => {
      try {
        const ws = new WebSocket("ws://localhost:8000/api/ws/threats");
        wsRef.current = ws;
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => { setWsConnected(false); setTimeout(connect, 5000); };
        ws.onerror = () => ws.close();
      } catch { /* no-op */ }
    };
    connect();
    return () => wsRef.current?.close();
  }, []);

  const alertCount = (backendStatus?.alerts || []).length;
  const providerOk = (k) => backendStatus?.providers?.[k];

  return (
    <div className="sb">
      <div className="sb-glow" />
      <div className="sb-logo">
        <div className="sb-logo-row">
          <svg viewBox="0 0 32 32" fill="none" style={{ width: 28, height: 28, flexShrink: 0 }}>
            <polygon points="16,1 31,9 31,23 16,31 1,23 1,9" fill="none" stroke="#00ff88" strokeWidth="1.4" />
            <polygon points="16,6 26,12 26,20 16,26 6,20 6,12" fill="rgba(0,255,136,.06)" stroke="#00ff88" strokeWidth=".7" />
            <circle cx="16" cy="16" r="4.5" fill="none" stroke="#00d4ff" strokeWidth="1.1" />
            <circle cx="16" cy="16" r="1.8" fill="#00ff88" />
            <line x1="16" y1="6.5" x2="16" y2="11.5" stroke="#00ff88" strokeWidth=".9" />
            <line x1="16" y1="20.5" x2="16" y2="25.5" stroke="#00ff88" strokeWidth=".9" />
            <line x1="6" y1="12" x2="11.5" y2="15" stroke="#00ff88" strokeWidth=".9" />
            <line x1="20.5" y1="17" x2="26" y2="20" stroke="#00ff88" strokeWidth=".9" />
          </svg>
          <span className="sb-wordmark">GhostTrace</span>
        </div>
        <div className="sb-tagline">Intelligence Beyond Visibility</div>
      </div>

      <div className="sb-nav">
        {NAV.map((s) => (
          <div key={s.section} className="sb-sec">
            <span className="sb-sec-lbl">{s.section}</span>
            {s.items.map((item) => {
              const isAlert = item.id === "intel" && alertCount > 0;
              return (
                <div
                  key={item.id}
                  className={`sb-item ${view === item.id ? "active" : ""}`}
                  onClick={() => setView(item.id)}
                >
                  <span className="sb-ic">{item.icon}</span>
                  <span style={{ flex: 1 }}>{item.label}</span>
                  {isAlert && (
                    <span style={{
                      background: "rgba(255,45,85,.14)", color: "var(--red)",
                      fontFamily: "var(--mono)", fontSize: 8.5, padding: "1px 5px",
                      borderRadius: 8, border: "1px solid rgba(255,45,85,.3)", flexShrink: 0
                    }}>
                      {alertCount}
                    </span>
                  )}
                  {item.badge && !isAlert && (
                    <span className="sb-badge">{item.badge}</span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      <div className="sb-footer">
        <div className="sb-status-row">
          <div className="sb-dot" style={{
            background: backendStatus?.authState === "ok" ? "var(--green)" : "var(--amber)",
            boxShadow: backendStatus?.authState === "ok" ? "0 0 7px var(--green)" : "0 0 7px var(--amber)"
          }} />
          <span>{backendStatus?.statusText || "Status unknown"}</span>
        </div>
        <div className="sb-status-row" style={{ marginLeft: 13 }}>
          <span>
            VT {providerOk("virustotal") ? "✓" : "•"}&nbsp;&nbsp;
            IPDB {providerOk("abuseipdb") ? "✓" : "•"}&nbsp;&nbsp;
            PT {providerOk("phishtank") ? "✓" : "•"}&nbsp;&nbsp;
            YR {backendStatus?.yara ? "✓" : "•"}
          </span>
        </div>
        {/* WebSocket real-time status */}
        <div className="sb-status-row" style={{ marginLeft: 13, marginTop: 2 }}>
          <div style={{
            width: 5, height: 5, borderRadius: "50%", flexShrink: 0,
            background: wsConnected ? "var(--cyan)" : "rgba(255,255,255,.2)",
            boxShadow: wsConnected ? "0 0 5px var(--cyan)" : "none"
          }} />
          <span style={{ fontSize: 8, color: wsConnected ? "var(--cyan)" : "var(--t3)" }}>
            {wsConnected ? "RT Feed Active" : "RT Feed Offline"}
          </span>
        </div>
      </div>
    </div>
  );
}
