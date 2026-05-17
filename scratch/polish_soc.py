
import sys
import os

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. ForensicTimeline for URLScanner
content = content.replace(
    """          {tab === "timeline" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">📅 Analysis Timeline</span></div>
              <div className="card-body">
                <div className="tl-wrap">
                  {r.url_timeline.map((ev, i) => (
                    <div key={i} className={`tl-event ${ev.sev}`}>
                      <div className="tl-time"><Badge level={ev.sev}>{ev.sev}</Badge><span>{ev.t}</span></div>
                      <div className="tl-card">
                        <div className="tl-title">{ev.e}</div>
                        <div className="tl-body">{ev.d}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}""",
    """          {tab === "timeline" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">📅 Forensic Analysis Timeline</span></div>
              <div className="card-body">
                <ForensicTimeline events={r.url_timeline.map(ev => ({ stage: ev.t, details: ev.d, sev: ev.sev }))} />
              </div>
            </div>
          )}"""
)

# 2. ForensicTimeline for LogAnalyzer
content = content.replace(
    """          {tab === "timeline" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">📅 Forensic Event Timeline — Full Attack Lifecycle</span></div>
              <div className="card-body">
                <div className="tl-wrap">
                  {r.timeline.map((ev, i) => (
                    <div key={i} className={`tl-event ${ev.sev}`}>
                      <div className="tl-time"><Badge level={ev.sev}>{ev.sev}</Badge><span className="mono">{ev.t}</span></div>
                      <div className="tl-card">
                        <div className="tl-title">{ev.e}</div>
                        <div className="tl-body">{ev.d}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}""",
    """          {tab === "timeline" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">📅 Forensic Event Timeline — Attack Chain Breakdown</span></div>
              <div className="card-body">
                <ForensicTimeline events={r.timeline.map(ev => ({ stage: ev.t, details: ev.d, sev: ev.sev }))} />
              </div>
            </div>
          )}"""
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Successfully polished SOC component usage in GhostTrace.jsx")
