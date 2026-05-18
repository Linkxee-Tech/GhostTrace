import React, { useState, useEffect, useRef } from "react";
import { TITLES } from "./SOCConstants";

export function Topbar({ view, backendStatus, historyItems = [], onSearch }) {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchVal, setSearchVal] = useState("");
  const [notifOpen, setNotifOpen] = useState(false);
  const searchRef = useRef(null);

  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (searchOpen && searchRef.current) searchRef.current.focus();
  }, [searchOpen]);

  // Key shortcut: Ctrl+K opens search
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen((v) => !v);
      }
      if (e.key === "Escape") { setSearchOpen(false); setNotifOpen(false); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const threatCount = historyItems.filter((s) =>
    ["critical", "high"].includes(String(s.level).toLowerCase())
  ).length;

  const recentThreats = historyItems
    .filter((s) => ["critical", "high", "medium"].includes(String(s.level).toLowerCase()))
    .slice(0, 5);

  const isConnected = backendStatus?.authState === "ok";
  const statusColor = isConnected ? "var(--green)" : "var(--amber)";
  const statusLabel = isConnected ? "Live" : (backendStatus?.authState === "missing_api_key" ? "Auth Required" : backendStatus?.authState === "invalid_api_key" ? "Auth Invalid" : "Offline");

  return (
    <div className="topbar" style={{ position: "relative" }}>
      {/* Title */}
      <div style={{ fontSize: 13.5, fontWeight: 700, flex: 1, display: "flex", alignItems: "center", gap: 8 }}>
        <img src="/ghosttrace_logo.png" alt="GhostTrace logo" className="brand-logo-topbar" />
        <span>{TITLES[view] || "GhostTrace"}</span>
        {threatCount > 0 && (
          <span style={{
            background: "rgba(255,45,85,.15)", color: "var(--red)", border: "1px solid rgba(255,45,85,.3)",
            borderRadius: 5, fontSize: 9, fontFamily: "var(--mono)", padding: "1px 6px", letterSpacing: ".5px", fontWeight: 700
          }}>
            {threatCount} HIGH RISK
          </span>
        )}
      </div>

      {/* Global Search */}
      {searchOpen ? (
        <div style={{
          display: "flex", alignItems: "center", gap: 8, background: "rgba(255,255,255,.06)",
          border: "1px solid rgba(59,130,246,.4)", borderRadius: 8, padding: "0 12px",
          height: 34, minWidth: 280, boxShadow: "0 0 16px rgba(59,130,246,.12)"
        }}>
          <span style={{ color: "var(--t3)", fontSize: 12 }}>🔍</span>
          <input
            ref={searchRef}
            value={searchVal}
            onChange={(e) => setSearchVal(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && onSearch) { onSearch(searchVal); setSearchOpen(false); setSearchVal(""); } }}
            placeholder="Search IOC, IP, hash, domain..."
            style={{ background: "none", border: "none", outline: "none", color: "var(--t1)", fontFamily: "var(--mono)", fontSize: 11.5, flex: 1 }}
          />
          <span style={{ color: "var(--t3)", fontFamily: "var(--mono)", fontSize: 9 }}>ESC</span>
        </div>
      ) : (
        <button
          onClick={() => setSearchOpen(true)}
          className="t-chip"
          style={{ cursor: "pointer", border: "1px solid var(--border)", borderRadius: 6, fontSize: 11, color: "var(--t3)", gap: 6, padding: "4px 10px", background: "rgba(255,255,255,.03)" }}
        >
          <span>🔍</span>
          <span style={{ fontFamily: "var(--mono)", fontSize: 9 }}>Search</span>
          <span style={{ fontFamily: "var(--mono)", fontSize: 8, color: "var(--t3)", background: "rgba(255,255,255,.05)", padding: "1px 5px", borderRadius: 3 }}>⌘K</span>
        </button>
      )}

      {/* Chips */}
      <div className="topbar-chips">
        <div className="t-chip" style={{ gap: 5 }}>
          <span className="live-dot" style={{ background: statusColor, boxShadow: `0 0 6px ${statusColor}` }} />
          <span style={{ fontFamily: "var(--mono)", fontSize: 9.5 }}>{statusLabel}</span>
        </div>
        <div className="t-chip" style={{ fontFamily: "var(--mono)", fontSize: 9.5 }}>🕐 {time}</div>
        <div className="t-chip" style={{ fontFamily: "var(--mono)", fontSize: 9.5 }}>⬡ v2.0</div>
        <div className="t-chip" style={{ fontFamily: "var(--mono)", fontSize: 9.5 }}>
          🛡 {backendStatus?.yara ? "YARA Active" : "YARA Unknown"}
        </div>

        {/* Notifications Bell */}
        <button
          onClick={() => setNotifOpen((v) => !v)}
          style={{
            position: "relative", background: "rgba(255,255,255,.03)", border: "1px solid var(--border)",
            borderRadius: 6, padding: "4px 9px", cursor: "pointer", fontSize: 13, color: "var(--t2)",
            display: "flex", alignItems: "center"
          }}
        >
          🔔
          {threatCount > 0 && (
            <span style={{
              position: "absolute", top: 2, right: 2, width: 7, height: 7, borderRadius: "50%",
              background: "var(--red)", boxShadow: "0 0 6px var(--red)"
            }} />
          )}
        </button>
      </div>

      {/* Notification Dropdown */}
      {notifOpen && (
        <div style={{
          position: "absolute", top: "calc(100% + 8px)", right: 16, zIndex: 999,
          background: "var(--card)", border: "1px solid var(--border2)", borderRadius: 10,
          minWidth: 320, boxShadow: "0 16px 48px rgba(0,0,0,.6)", overflow: "hidden"
        }}>
          <div style={{ padding: "11px 15px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11.5, fontWeight: 700 }}>🔔 Active Alerts</span>
            <span style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--t3)" }}>{recentThreats.length} events</span>
          </div>
          {recentThreats.length === 0 ? (
            <div style={{ padding: "20px 15px", textAlign: "center", color: "var(--t3)", fontFamily: "var(--mono)", fontSize: 10 }}>
              No active threats detected
            </div>
          ) : (
            recentThreats.map((t, i) => (
              <div key={i} style={{
                padding: "10px 15px", borderBottom: "1px solid var(--border)",
                display: "flex", alignItems: "center", gap: 10
              }}>
                <div style={{
                  width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                  background: t.level === "critical" ? "var(--red)" : t.level === "high" ? "var(--amber)" : "var(--blue)",
                  boxShadow: `0 0 6px ${t.level === "critical" ? "var(--red)" : "var(--amber)"}`
                }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11.5, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.name}</div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--t3)" }}>{String(t.type).toUpperCase()} · {String(t.level).toUpperCase()} · {t.date}</div>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

