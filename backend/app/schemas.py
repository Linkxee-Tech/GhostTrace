from pydantic import BaseModel
from typing import Any


class TimelineEvent(BaseModel):
    stage: str
    details: str


class AnalysisResult(BaseModel):
    filename: str
    file_type: str
    entropy: float
    hashes: dict[str, str]
    suspicious_strings: list[str]
    iocs: dict[str, list[str]]
    ai_summary: str
    timeline: list[TimelineEvent]
    recommendations: list[str]
    risk: dict[str, Any]


class UrlAnalysisRequest(BaseModel):
    url: str


class LogAnalysisRequest(BaseModel):
    log_text: str


class UrlAnalysisResult(BaseModel):
    input_url: str
    domain: str
    risk_score: int
    threat_level: str
    confidence: int
    threat_explanation: str
    findings: list[str]
    malware_injection_findings: list[str]
    vulnerability_findings: list[str]
    suspicious_behaviors_detected: int
    iocs: list[dict[str, str]]
    website_compromise_indicators: list[str]
    security_feedback: dict[str, Any]
    page_artifacts: dict[str, Any]
    threat_intel_mapping: dict[str, Any]
    reputation_signals: dict[str, Any]
    health_breakdown: dict[str, int]
    possible_attack_chain: list[str]
    recommendations: list[str]


class MonitorAddRequest(BaseModel):
    url: str


class ApiKeysUpdateRequest(BaseModel):
    ghosttrace_api_key: str | None = None
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    openai_api_key: str | None = None
    urlscan_api_key: str | None = None
    phishtank_api_key: str | None = None


class UnifiedInvestigationResult(BaseModel):
    target: str
    type: str  # 'file', 'url', or 'log'
    risk_score: int
    severity: str  # 'low', 'medium', 'high', 'critical'
    confidence: int
    iocs: list[dict[str, str]]
    timeline: list[dict[str, Any]]
    ai_explanation: str
    recommendations: list[str]
    health_breakdown: dict[str, int] | None = None
    mitre_mapping: list[dict[str, str]] | None = None
    raw_artifacts: dict[str, Any] | None = None
    evidence: list[str] | None = None
