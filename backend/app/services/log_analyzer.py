import json
import os
import re
from typing import Any
from urllib.error import URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from app.schemas import UnifiedInvestigationResult
from app.services.llm_fallback import generate_with_fallback


def _safe_get_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    req = Request(url, headers=headers or {})
    try:
        with urlopen(req, timeout=8) as resp:  # nosec B310 - defensive intel lookup only
            return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except (URLError, TimeoutError, ValueError):
        return None


def _lookup_abuseipdb(ip: str) -> dict[str, Any]:
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        return {"available": False, "reason": "ABUSEIPDB_API_KEY missing"}
    data = _safe_get_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote_plus(ip)}&maxAgeInDays=90",
        headers={"Key": key, "Accept": "application/json"},
    )
    if not data or "data" not in data:
        return {"available": False, "reason": "AbuseIPDB lookup unavailable"}
    return {
        "available": True,
        "abuse_confidence_score": int(data["data"].get("abuseConfidenceScore", 0)),
        "country_code": data["data"].get("countryCode"),
        "usage_type": data["data"].get("usageType"),
        "total_reports": int(data["data"].get("totalReports", 0)),
    }


def _lookup_virustotal_domain(domain: str) -> dict[str, Any]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY missing"}
    data = _safe_get_json(
        f"https://www.virustotal.com/api/v3/domains/{quote_plus(domain)}",
        headers={"x-apikey": key},
    )
    if not data:
        return {"available": False, "reason": "VirusTotal lookup unavailable"}
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "available": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
    }


def _lookup_phishtank(domain: str) -> dict[str, Any]:
    key = os.getenv("PHISHTANK_API_KEY", "").strip()
    if not key:
        return {"available": False, "reason": "PHISHTANK_API_KEY missing"}
    data = _safe_get_json(
        "https://checkurl.phishtank.com/checkurl/"
        f"?url={quote_plus('http://' + domain)}&format=json&app_key={quote_plus(key)}"
    )
    if not data:
        return {"available": False, "reason": "PhishTank lookup unavailable"}
    results = data.get("results", {})
    return {
        "available": True,
        "in_database": bool(results.get("in_database", False)),
        "valid": bool(results.get("valid", False)),
        "phish": bool(results.get("in_database", False) and results.get("valid", False)),
    }


def _generate_log_ai_explanation(text: str, behavior_patterns: list[str], risk_score: int) -> str:
    if not os.getenv("OPENAI_API_KEY", "").strip() and not os.getenv("GROQ_API_KEY", "").strip():
        return (
            "AI explanation unavailable because OPENAI_API_KEY is not configured. "
            "Returning deterministic log findings."
        )
    prompt = (
        "You are a defensive SOC analyst. Explain suspicious behavior in these logs.\n"
        f"Risk score: {risk_score}\n"
        f"Behavior patterns: {behavior_patterns}\n"
        f"Log excerpt:\n{text[:3500]}\n"
        "Provide 4-6 concise evidence-based sentences and immediate defensive actions."
    )
    text_out = generate_with_fallback(prompt, max_tokens=220, primary_model="gpt-4.1-mini")
    if text_out:
        return text_out
    return "AI explanation service could not be reached. Deterministic behavioral findings are provided."


def analyze_log_text(log_text: str) -> UnifiedInvestigationResult:
    text = log_text.strip()
    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b", text)
    command_matches = re.findall(r"\b(?:powershell|cmd\.exe|bash|curl|wget)[^\r\n]*", text, flags=re.IGNORECASE)
    behavior_patterns = []

    if re.search(r"failed login|authentication failure|brute", text, flags=re.IGNORECASE):
        behavior_patterns.append("Credential attack attempts")
    if re.search(r"encodedcommand|base64|invoke-expression", text, flags=re.IGNORECASE):
        behavior_patterns.append("Obfuscated command execution")
    if re.search(r"scheduled task|autorun|run key|registry", text, flags=re.IGNORECASE):
        behavior_patterns.append("Persistence indicators")
    if re.search(r"download|http|https|dns", text, flags=re.IGNORECASE):
        behavior_patterns.append("Network callback behavior")

    risk_score = min(100, 20 + len(ip_matches) * 4 + len(command_matches) * 7 + len(behavior_patterns) * 12)

    unique_ips = sorted(set(ip_matches))
    unique_domains = sorted(set(domain_matches))
    abuse_results = {ip: _lookup_abuseipdb(ip) for ip in unique_ips[:30]}
    vt_domain_results = {d: _lookup_virustotal_domain(d) for d in unique_domains[:30]}
    phishtank_results = {d: _lookup_phishtank(d) for d in unique_domains[:30]}

    abuse_hits = sum(
        1
        for result in abuse_results.values()
        if result.get("available") and int(result.get("abuse_confidence_score", 0)) >= 60
    )
    vt_hits = sum(
        1
        for result in vt_domain_results.values()
        if result.get("available")
        and (int(result.get("malicious", 0)) > 0 or int(result.get("suspicious", 0)) > 0)
    )
    pt_hits = sum(1 for result in phishtank_results.values() if result.get("available") and result.get("phish") is True)
    risk_score = min(100, risk_score + (abuse_hits * 12) + (vt_hits * 10) + (pt_hits * 12))

    threat_level = "low"
    if risk_score >= 80:
        threat_level = "critical"
    elif risk_score >= 60:
        threat_level = "high"
    elif risk_score >= 35:
        threat_level = "medium"

    explanation = _generate_log_ai_explanation(
        text,
        behavior_patterns or ["No high-confidence behavior patterns identified."],
        risk_score,
    )

    iocs = []
    for ip in unique_ips:
        iocs.append({"type": "ip", "value": ip})
    for dom in unique_domains:
        iocs.append({"type": "domain", "value": dom})
    for cmd in sorted(set(command_matches)):
        iocs.append({"type": "command", "value": cmd})

    timeline = [
        {"stage": "Log Ingestion", "details": f"Analyzed {len(text.splitlines())} log lines.", "sev": "low"},
    ]
    if behavior_patterns:
        timeline.append(
            {
                "stage": "Pattern Match",
                "details": f"Identified: {', '.join(behavior_patterns)}",
                "sev": "medium" if risk_score < 60 else "high",
            }
        )
    if abuse_hits or vt_hits or pt_hits:
        timeline.append(
            {
                "stage": "Live Threat Intel Correlation",
                "details": (
                    f"Matched {abuse_hits} high-risk IP(s), {vt_hits} suspicious/malicious domain(s), "
                    f"and {pt_hits} phishing domain indicator(s) from external intelligence sources."
                ),
                "sev": "high" if (abuse_hits + vt_hits + pt_hits) > 1 else "medium",
            }
        )
    timeline.append({"stage": "AI Analysis", "details": "Generated attack reconstruction from log events.", "sev": "low"})

    return UnifiedInvestigationResult(
        target="System Logs",
        type="log",
        risk_score=risk_score,
        severity=threat_level,
        confidence=min(95, 45 + len(behavior_patterns) * 10 + (abuse_hits + vt_hits + pt_hits) * 5),
        iocs=iocs,
        timeline=timeline,
        ai_explanation=explanation,
        recommendations=[
            "Identify and isolate the source IP addresses detected in brute force patterns.",
            "Review audit logs for successful logins following brute force attempts.",
            "Rotate credentials for any accounts appearing in the log excerpt.",
        ],
        raw_artifacts={
            "behavior_patterns": behavior_patterns,
            "ip_matches": unique_ips,
            "domain_matches": unique_domains,
            "threat_intel": {
                "abuseipdb": abuse_results,
                "virustotal_domains": vt_domain_results,
                "phishtank": phishtank_results,
            },
            "threat_intel_hits": {
                "abuseipdb_high_risk_ip_hits": abuse_hits,
                "virustotal_domain_hits": vt_hits,
                "phishtank_hits": pt_hits,
            },
        },
    )
