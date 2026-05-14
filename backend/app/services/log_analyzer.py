import re
import os
from typing import Any

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None


def _generate_log_ai_explanation(text: str, behavior_patterns: list[str], risk_score: int) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return (
            "AI explanation unavailable because OPENAI_API_KEY is not configured. "
            "Returning deterministic log findings."
        )
    try:
        client = OpenAI(api_key=api_key)
        prompt = (
            "You are a defensive SOC analyst. Explain suspicious behavior in these logs.\n"
            f"Risk score: {risk_score}\n"
            f"Behavior patterns: {behavior_patterns}\n"
            f"Log excerpt:\n{text[:3500]}\n"
            "Provide 4-6 concise evidence-based sentences and immediate defensive actions."
        )
        resp = client.responses.create(model="gpt-4.1-mini", input=prompt, max_output_tokens=220)
        return (resp.output_text or "").strip() or "AI explanation returned empty output."
    except Exception:
        return (
            "AI explanation service could not be reached. Deterministic behavioral findings are provided."
        )


def analyze_log_text(log_text: str) -> dict[str, Any]:
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
    threat_level = "safe"
    if risk_score >= 80:
        threat_level = "critical"
    elif risk_score >= 60:
        threat_level = "high"
    elif risk_score >= 35:
        threat_level = "suspicious"

    return {
        "iocs": {
            "ips": sorted(set(ip_matches)),
            "domains": sorted(set(domain_matches)),
            "suspicious_commands": sorted(set(command_matches)),
        },
        "behavior_patterns": behavior_patterns or ["No high-confidence behavior patterns identified."],
        "risk_score": risk_score,
        "threat_level": threat_level,
        "ai_explanation": _generate_log_ai_explanation(
            text,
            behavior_patterns or ["No high-confidence behavior patterns identified."],
            risk_score,
        ),
    }
