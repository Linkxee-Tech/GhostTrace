import React, { useState, useEffect } from "react";
import { TITLES } from "./SOCConstants";

export function Topbar({ view, backendStatus }) {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="topbar">
      <div style={{ fontSize:13.5, fontWeight:700, flex:1 }}>📡 {TITLES[view] || "GhostTrace"}</div>
      <div className="topbar-chips">
        <div className="t-chip"><span className="live-dot" style={{ background: backendStatus?.connected ? "var(--green)" : "var(--amber)" }} />{backendStatus?.connected ? "Live" : (backendStatus?.authState === "missing_api_key" ? "Auth Required" : backendStatus?.authState === "invalid_api_key" ? "Auth Invalid" : "Offline")}</div>
        <div className="t-chip">🕐 {time}</div>
        <div className="t-chip">⬡ v2.0</div>
        <div className="t-chip">🛡 {backendStatus?.yara ? "YARA Active" : "YARA Unknown"}</div>
      </div>
    </div>
  );
}
