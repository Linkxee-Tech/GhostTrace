import React from "react";
import { SecHd } from "./SOCLibrary";

export function Terms() {
  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize: 24, fontWeight: 800, marginBottom: 5 }}>📜 Terms of Service</div>
        <div className="txt-sec txt-sm">Authorized Use, Liability, and Platform Restrictions</div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">1. Acceptance of Terms</span></div>
        <div className="card-body">
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            By accessing or using the GhostTrace platform ("Service"), you agree to be bound by these Terms of Service. If you do not agree with any part of these terms, you are prohibited from using the Service. GhostTrace is a B2B cybersecurity tool intended strictly for authorized security personnel, incident responders, and researchers.
          </p>
        </div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">2. Authorized Use & Acceptable Behavior</span></div>
        <div className="card-body">
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            You may use GhostTrace strictly for lawful cybersecurity investigation, threat intelligence gathering, and defensive operations. 
          </p>
          <ul className="txt-sec" style={{ paddingLeft: 20, lineHeight: 1.6, marginBottom: 0 }}>
            <li>You must have explicit authorization to scan, upload, or analyze assets belonging to your organization or your clients.</li>
            <li>You may not use GhostTrace to facilitate offensive cyber operations, reconnaissance for malicious intent, or to evade security controls.</li>
            <li>Reverse engineering the platform, scraping intelligence data, or attempting to exploit the backend infrastructure is strictly prohibited.</li>
          </ul>
        </div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">3. Passive Analysis Limitations</span></div>
        <div className="card-body">
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            GhostTrace performs passive and non-destructive dynamic analysis. The platform does not perform active exploitation, credential testing, or invasive vulnerability scanning against live targets. You acknowledge that risk scores and threat severities are algorithmic approximations and should not replace human judgment or rigorous penetration testing.
          </p>
        </div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">4. API Limits & Fair Use</span></div>
        <div className="card-body">
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            Usage of the GhostTrace platform is subject to rate limiting and fair use policies to ensure stability for all tenants. Excessive API calls or automated bulk submissions that degrade system performance may result in temporary rate-limiting or account suspension.
          </p>
        </div>
      </div>

      <div className="card">
        <div className="card-hd"><span className="card-title">5. Limitation of Liability</span></div>
        <div className="card-body">
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            GhostTrace is provided "AS IS" without any warranty of any kind, whether express or implied. We do not warrant that the intelligence provided is 100% accurate, complete, or free of false positives.
          </p>
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            In no event shall GhostTrace, its founders, or affiliates be liable for any indirect, incidental, special, consequential, or punitive damages, including loss of profits, data, or business interruption, arising out of your use or inability to use the Service or the intelligence reports it generates.
          </p>
        </div>
      </div>
    </div>
  );
}
