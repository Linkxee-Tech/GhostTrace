import React from "react";
import { SecHd } from "./SOCLibrary";

export function About() {
  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize: 24, fontWeight: 800, marginBottom: 5 }}>ℹ️ About GhostTrace</div>
        <div className="txt-sec txt-sm">Intelligence Beyond Visibility · AI-Powered Threat Investigation Platform</div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">Executive Summary</span></div>
        <div className="card-body">
          <p style={{ lineHeight: 1.6, marginBottom: 12 }}>
            <strong>GhostTrace</strong> is an elite cybersecurity intelligence and investigation platform engineered for modern Security Operations Centers (SOC), incident responders, and digital forensic analysts.
          </p>
          <p style={{ lineHeight: 1.6 }}>
            By unifying advanced static/dynamic analysis, global threat intelligence syndication, and AI-driven attack reconstruction, GhostTrace transforms raw data artifacts into actionable, tactical intelligence. Our mission is to accelerate incident response times, reduce false positives, and provide analysts with a comprehensive, single-pane-of-glass view into complex cyber threats.
          </p>
        </div>
      </div>

      <div className="feat-grid mb16">
        <div className="feat-card">
          <div className="feat-icon">📁</div>
          <div className="feat-name">Deep File Forensics</div>
          <div className="feat-desc">Extract entropy, hashes, packed sections, and string artifacts. Match against YARA rules and identify process injection techniques.</div>
        </div>
        <div className="feat-card">
          <div className="feat-icon">🌐</div>
          <div className="feat-name">Web & Phishing Intelligence</div>
          <div className="feat-desc">Passively analyze domains, resolve DNS infrastructure, inspect SSL certificates, and detect credential harvesting forms and iframe injections.</div>
        </div>
        <div className="feat-card">
          <div className="feat-icon">📋</div>
          <div className="feat-name">Log Behavioral Analysis</div>
          <div className="feat-desc">Ingest raw auth.log, syslog, or WinEvent logs to detect brute-force attempts, lateral movement, and persistent C2 beaconing.</div>
        </div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">Platform Architecture</span></div>
        <div className="card-body">
          <SecHd>Global Intelligence Syndication</SecHd>
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            GhostTrace integrates with industry-leading threat intelligence providers including VirusTotal, AbuseIPDB, URLScan.io, and PhishTank. This provides an aggregated, real-time reputation score across billions of known threat indicators.
          </p>
          <SecHd>AI Threat Reconstruction</SecHd>
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            Utilizing state-of-the-art Large Language Models, GhostTrace synthesizes fragmented artifacts into coherent attack narratives, automatically mapping findings to the MITRE ATT&CK® framework and generating actionable remediation steps.
          </p>
          <SecHd>Enterprise Reporting</SecHd>
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            Instantly generate standardized, forensic PDF reports for any investigation. Reports include full IOC extraction, timeline analysis, and risk scoring, ready for executive review or compliance auditing.
          </p>
        </div>
      </div>

      <div className="card">
        <div className="card-body" style={{ textAlign: "center", padding: "40px 20px" }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>🛡️</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Ready for Enterprise Security Operations</div>
          <div className="txt-sec" style={{ maxWidth: 600, margin: "0 auto" }}>
            GhostTrace is built on a scalable, modular architecture designed to integrate seamlessly into existing security pipelines, ensuring your team has the intelligence they need, exactly when they need it.
          </div>
        </div>
      </div>
    </div>
  );
}
