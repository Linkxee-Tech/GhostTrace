import hashlib
import math
import re
from typing import Any
from fastapi import UploadFile
from app.services.ioc_extractor import extract_iocs
from app.services.ai_engine import explain_behavior
from app.schemas import AnalysisResult, TimelineEvent
from app.services.yara_scanner import yara_scan_content


def compute_hashes(content: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def compute_entropy(content: bytes) -> float:
    if not content:
        return 0.0
    frequency = [0] * 256
    for byte in content:
        frequency[byte] += 1
    entropy = 0.0
    length = len(content)
    for count in frequency:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def find_suspicious_strings(content: bytes) -> list[str]:
    decoded = content.decode("utf-8", errors="ignore")
    findings = set()
    for pattern in [b"http", b"https", b"ftp", b"powershell", b"cmd.exe", b"/c", b"Invoke-Expression"]:
        if pattern.decode("utf-8", errors="ignore") in decoded:
            findings.add(pattern.decode("utf-8", errors="ignore"))
    for regex in [r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", r"https?://[^\s'\"]+", r"\\\d{1,3}(?:\\.\\d{1,3}){3}"]:
        for match in re.findall(regex, decoded):
            findings.add(match)
    return sorted(findings)


def compute_risk_score(analysis: AnalysisResult) -> dict[str, Any]:
    score = 0
    if analysis.entropy >= 7.0:
        score += 2
    if analysis.iocs and any(analysis.iocs.values()):
        score += 2
    if analysis.suspicious_strings:
        score += 1
    if analysis.file_type in {"PE executable", "ELF executable", "Windows executable"}:
        score += 1

    if score >= 5:
        severity = "critical"
        confidence = 91
    elif score >= 4:
        severity = "high"
        confidence = 78
    elif score >= 2:
        severity = "suspicious"
        confidence = 56
    else:
        severity = "safe"
        confidence = 24

    explanation = (
        f"Risk set to {severity} based on entropy ({analysis.entropy}), "
        f"{len(analysis.suspicious_strings)} suspicious string findings, and IOC presence."
    )

    return {
        "severity": severity,
        "confidence": confidence,
        "score": score,
        "explanation": explanation,
    }


def detect_file_type(content: bytes, filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".exe") or content[:2] == b"MZ":
        return "PE executable"
    if lower.endswith(".elf"):
        return "ELF executable"
    if lower.endswith(".js"):
        return "JavaScript"
    if lower.endswith(".ps1"):
        return "PowerShell script"
    if lower.endswith(".doc") or lower.endswith(".docx"):
        return "Office document"
    if lower.endswith(".zip") or lower.endswith(".rar") or lower.endswith(".7z"):
        return "Archive"
    if lower.endswith(".pdf"):
        return "PDF document"
    return "Unknown"


def build_timeline(
    file_type: str, suspicious_strings: list[str], iocs: dict[str, list[str]]
) -> list[TimelineEvent]:
    timeline = [TimelineEvent(stage="initial_execution", details=f"Sample classified as {file_type}.")]
    if suspicious_strings:
        timeline.append(
            TimelineEvent(
                stage="artifact_observation",
                details=f"Detected suspicious strings: {', '.join(suspicious_strings[:5])}.",
            )
        )
    if iocs.get("urls") or iocs.get("ips") or iocs.get("domains"):
        timeline.append(
            TimelineEvent(
                stage="network_activity",
                details="Potential network communication indicators were extracted.",
            )
        )
    if iocs.get("registry_keys"):
        timeline.append(
            TimelineEvent(
                stage="persistence",
                details="Registry-related indicators suggest persistence attempts.",
            )
        )
    if iocs.get("suspicious_commands"):
        timeline.append(
            TimelineEvent(
                stage="execution_behavior",
                details="Suspicious shell commands imply scripted or command-line execution.",
            )
        )
    yara_info = iocs.get("yara_rule_matches", [])
    if yara_info:
        timeline.append(
            TimelineEvent(
                stage="signature_detection",
                details=f"YARA rule matches detected: {', '.join(yara_info)}.",
            )
        )
    return timeline


def build_recommendations(risk_severity: str) -> list[str]:
    base = [
        "Preserve the sample and related artifacts with chain-of-custody metadata.",
        "Correlate extracted IOCs against SIEM/EDR telemetry and threat intel feeds.",
    ]
    if risk_severity in {"high", "critical"}:
        return base + [
            "Isolate the affected host from the network pending triage.",
            "Block matched IOC domains/IPs at perimeter and endpoint controls.",
            "Acquire memory and disk images for deeper forensic analysis.",
        ]
    if risk_severity == "suspicious":
        return base + [
            "Run the sample in an isolated sandbox for dynamic behavior confirmation.",
            "Monitor hosts for recurrence of extracted commands and indicators.",
        ]
    return base + ["No immediate containment required; continue monitoring for related activity."]


async def analyze_file(file: UploadFile) -> AnalysisResult:
    content = await file.read()
    hashes = compute_hashes(content)
    entropy = compute_entropy(content)
    suspicious_strings = find_suspicious_strings(content)
    iocs = extract_iocs(content)
    yara_result = yara_scan_content(content)
    iocs["yara_rule_matches"] = yara_result.get("matches", [])
    file_type = detect_file_type(content, file.filename)
    ai_summary = explain_behavior(file.filename, file_type, suspicious_strings, iocs)
    risk = compute_risk_score(AnalysisResult(
        filename=file.filename,
        file_type=file_type,
        entropy=entropy,
        hashes=hashes,
        suspicious_strings=suspicious_strings,
        iocs=iocs,
        ai_summary=ai_summary,
        timeline=[],
        recommendations=[],
        risk={},
    ))
    timeline = build_timeline(file_type, suspicious_strings, iocs)
    recommendations = build_recommendations(risk["severity"])

    return AnalysisResult(
        filename=file.filename,
        file_type=file_type,
        entropy=entropy,
        hashes=hashes,
        suspicious_strings=suspicious_strings,
        iocs=iocs,
        ai_summary=ai_summary,
        timeline=timeline,
        recommendations=recommendations,
        risk=risk,
    )
