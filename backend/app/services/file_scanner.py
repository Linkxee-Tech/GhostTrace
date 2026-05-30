import hashlib
import json
import math
import os
import re
from urllib.error import URLError
from urllib.request import Request, urlopen
from typing import Any
from fastapi import UploadFile
from app.services.ioc_extractor import extract_iocs
from app.services.ai_engine import explain_behavior, get_mitre_mapping
from app.schemas import AnalysisResult, TimelineEvent, InvestigationResult
from app.services.yara_scanner import yara_scan_content


def _virustotal_hash_lookup(sha256_hash: str) -> dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY missing"}

    req = Request(
        f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
        headers={"x-apikey": api_key},
    )
    try:
        with urlopen(req, timeout=8) as resp:  # nosec B310 - defensive intel lookup
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except (URLError, TimeoutError, ValueError):
        return {"available": False, "reason": "VirusTotal lookup failed"}

    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "available": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
    }


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
    # Extract strings in both UTF-8 and UTF-16 (common in Windows binaries)
    findings = set()
    try:
        utf8_text = content.decode("utf-8", errors="ignore")
        utf16_text = content.decode("utf-16", errors="ignore")
    except Exception:
        utf8_text = content.decode("latin-1", errors="ignore")
        utf16_text = ""

    combined_text = utf8_text + " " + utf16_text
    
    keywords = [
        "http", "https", "ftp", "powershell", "cmd.exe", "/c", "Invoke-Expression",
        "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory", "GetProcAddress",
        "LoadLibrary", "RegSetValue", "IsDebuggerPresent", "WinExec"
    ]
    
    for kw in keywords:
        if kw.lower() in combined_text.lower():
            findings.add(kw)
            
    # Add regex patterns
    for regex in [r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", r"https?://[^\s'\"]+", r"\\\d{1,3}(?:\\.\\d{1,3}){3}"]:
        for match in re.findall(regex, combined_text):
            findings.add(match)
            
    return sorted(findings)


def compute_risk_score(analysis: Any, yara_matches: list[str], vt: dict[str, Any] | None = None) -> dict[str, Any]:
    score = 0
    # Entropy weight
    if analysis.entropy >= 7.2:
        score += 25
    elif analysis.entropy >= 6.5:
        score += 15
        
    # YARA weight (Strong signal)
    if yara_matches:
        score += 40
        if any("malware" in m.lower() or "trojan" in m.lower() for m in yara_matches):
            score += 20
            
    # IOC weight
    ioc_count = sum(len(v) for v in analysis.iocs.values() if isinstance(v, list))
    if ioc_count > 5:
        score += 20
    elif ioc_count > 0:
        score += 10
        
    # Suspicious strings
    if len(analysis.suspicious_strings) > 10:
        score += 15
    elif len(analysis.suspicious_strings) > 0:
        score += 5
        
    # Executable type
    if analysis.file_type in {"PE executable", "ELF executable"}:
        score += 5

    if vt and vt.get("available"):
        if int(vt.get("malicious", 0)) > 0:
            score += 30
        elif int(vt.get("suspicious", 0)) > 0:
            score += 15

    score = min(score, 100)
    
    if score >= 80:
        severity = "critical"
        confidence = 92
    elif score >= 60:
        severity = "high"
        confidence = 80
    elif score >= 30:
        severity = "medium"
        confidence = 65
    else:
        severity = "low"
        confidence = 30
        if score < 10:
            severity = "clean" if not yara_matches else "low"

    vt_note = ""
    if vt and vt.get("available"):
        vt_note = (
            f", VirusTotal verdicts (malicious={int(vt.get('malicious', 0))}, "
            f"suspicious={int(vt.get('suspicious', 0))})"
        )
    explanation = (
        f"Risk score of {score} determined by entropy ({analysis.entropy}), "
        f"YARA hits ({len(yara_matches)}), and {len(analysis.suspicious_strings)} suspicious strings{vt_note}."
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
) -> list[dict[str, Any]]:
    timeline = [{"stage": "Initial Analysis", "details": f"File identified as {file_type}.", "sev": "low"}]
    
    if suspicious_strings:
        timeline.append({
            "stage": "Static Observation",
            "details": f"Extracted {len(suspicious_strings)} suspicious strings including obfuscation keywords.",
            "sev": "medium"
        })
        
    if iocs.get("yara_rule_matches"):
        timeline.append({
            "stage": "Signature Match",
            "details": f"YARA signatures matched: {', '.join(iocs['yara_rule_matches'][:3])}.",
            "sev": "high"
        })

    if iocs.get("urls") or iocs.get("ips"):
        timeline.append({
            "stage": "Network Capability",
            "details": "Embedded network indicators suggest potential C2 or download behavior.",
            "sev": "medium"
        })
        
    return timeline


def build_recommendations(risk_severity: str) -> list[str]:
    base = [
        "Quarantine the file immediately and prevent execution.",
        "Correlate hashes and IPs against organizational SIEM/EDR logs.",
    ]
    if risk_severity in {"high", "critical"}:
        return base + [
            "Initiate incident response for the source endpoint.",
            "Block extracted domains/IPs at the perimeter firewall.",
            "Perform memory forensics on any host where this file was executed.",
        ]
    return base + ["Continue monitoring for related indicators of compromise."]


async def analyze_file(file: UploadFile) -> InvestigationResult:
    content = await file.read()
    hashes = compute_hashes(content)
    vt = _virustotal_hash_lookup(hashes["sha256"])
    entropy = compute_entropy(content)
    suspicious_strings = find_suspicious_strings(content)
    iocs = extract_iocs(content)
    yara_result = yara_scan_content(content)
    yara_matches = yara_result.get("matches", [])
    iocs["yara_rule_matches"] = yara_matches
    
    file_type = detect_file_type(content, file.filename)
    ai_summary = explain_behavior(file.filename, file_type, suspicious_strings, iocs)
    
    # Temporary object for risk scoring
    temp_result = type('obj', (object,), {
        'entropy': entropy,
        'iocs': iocs,
        'suspicious_strings': suspicious_strings,
        'file_type': file_type
    })
    
    risk = compute_risk_score(temp_result, yara_matches, vt=vt)
    timeline = build_timeline(file_type, suspicious_strings, iocs)
    if vt.get("available"):
        timeline.append(
            {
                "stage": "Threat Intel Correlation",
                "details": (
                    "Correlated file hash with VirusTotal: "
                    f"{int(vt.get('malicious', 0))} malicious and {int(vt.get('suspicious', 0))} suspicious engines."
                ),
                "sev": "high" if int(vt.get("malicious", 0)) > 0 else "medium",
            }
        )
    recommendations = build_recommendations(risk["severity"])

    # Flatten IOCs for unified model
    flat_iocs = []
    for k, v in iocs.items():
        if isinstance(v, list):
            for val in v:
                flat_iocs.append({"type": k.rstrip('s'), "value": str(val)})

    return InvestigationResult(
        target=file.filename,
        type="file",
        risk_score=risk["score"],
        severity=risk["severity"],
        confidence=risk["confidence"],
        iocs=flat_iocs,
        timeline=timeline,
        ai_explanation=ai_summary,
        recommendations=recommendations,
        mitre_mapping=get_mitre_mapping(suspicious_strings + yara_matches),
        raw_artifacts={
            "file_type": file_type,
            "entropy": entropy,
            "hashes": hashes,
            "yara_matches": yara_matches,
            "file_size": len(content),
            "virustotal": vt,
        }
    )
