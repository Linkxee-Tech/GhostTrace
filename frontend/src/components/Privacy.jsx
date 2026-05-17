import React from "react";
import { SecHd } from "./SOCLibrary";

export function Privacy() {
  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize: 24, fontWeight: 800, marginBottom: 5 }}>🔒 Privacy Policy</div>
        <div className="txt-sec txt-sm">Data Handling, Security, and Compliance Information</div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">1. Introduction</span></div>
        <div className="card-body">
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            GhostTrace ("we", "our", "us") is committed to protecting the privacy and security of our users. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our cybersecurity intelligence platform. By using the Service, you agree to the collection and use of information in accordance with this policy.
          </p>
        </div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">2. Data Collection & Investigation Artifacts</span></div>
        <div className="card-body">
          <SecHd>Submitted Artifacts</SecHd>
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            When you use GhostTrace to perform investigations, you may submit files, URLs, log excerpts, IP addresses, and other indicators of compromise (IOCs). This data is processed strictly for the purpose of threat analysis and intelligence generation.
          </p>
          <SecHd>Account Information</SecHd>
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            We collect standard account information (such as email addresses, role configurations, and access logs) required to authenticate users, enforce role-based access control (RBAC), and maintain system security and audit trails.
          </p>
        </div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">3. Third-Party Integrations & Data Sharing</span></div>
        <div className="card-body">
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            GhostTrace acts as an intelligence aggregator. To provide comprehensive analysis, submitted artifacts (such as file hashes or URLs) may be queried against third-party threat intelligence providers.
          </p>
          <ul className="txt-sec" style={{ paddingLeft: 20, lineHeight: 1.6, marginBottom: 0 }}>
            <li><strong>Reputation Providers:</strong> Indicators may be checked against VirusTotal, AbuseIPDB, URLScan.io, and PhishTank.</li>
            <li><strong>AI Services:</strong> Anonymized behavioral data or code snippets may be sent to OpenAI models for attack reconstruction. We do NOT permit third parties to use your submitted artifacts to train their models.</li>
          </ul>
        </div>
      </div>

      <div className="card mb16">
        <div className="card-hd"><span className="card-title">4. Data Retention & Security</span></div>
        <div className="card-body">
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            We implement enterprise-grade security measures designed to secure your personal and investigative data from accidental loss and from unauthorized access, use, alteration, and disclosure.
          </p>
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            <strong>Retention:</strong> Investigation reports and scan histories are retained within your tenant workspace according to your organization's configured data retention policy. Uploaded files are processed ephemerally or stored securely pending automated deletion schedules.
          </p>
        </div>
      </div>

      <div className="card">
        <div className="card-hd"><span className="card-title">5. Compliance & Contact</span></div>
        <div className="card-body">
          <p className="txt-sec mb12" style={{ lineHeight: 1.6 }}>
            GhostTrace complies with applicable data protection regulations. Users in relevant jurisdictions have rights regarding data access, rectification, and erasure.
          </p>
          <p className="txt-sec" style={{ lineHeight: 1.6 }}>
            For privacy-related inquiries, data deletion requests, or compliance auditing, please contact our Data Protection Officer (DPO) at <strong>privacy@ghosttrace.com</strong>.
          </p>
        </div>
      </div>
    </div>
  );
}
