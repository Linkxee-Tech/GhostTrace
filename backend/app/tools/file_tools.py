import hashlib
import math
import re
from typing import Any

def extract_file_artifacts(content: bytes) -> dict[str, Any]:
    """Extracts hashes, entropy, strings, and suspicious flags from a file."""
    if not content:
        return {"error": "Empty content"}
        
    # Hashes
    hashes = {
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    
    # Entropy
    frequency = [0] * 256
    for byte in content:
        frequency[byte] += 1
    entropy = 0.0
    length = len(content)
    for count in frequency:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    entropy = round(entropy, 4)
    
    # Strings
    try:
        utf8_text = content.decode("utf-8", errors="ignore")
        utf16_text = content.decode("utf-16", errors="ignore")
    except Exception:
        utf8_text = content.decode("latin-1", errors="ignore")
        utf16_text = ""

    combined_text = utf8_text + " " + utf16_text
    
    findings = set()
    keywords = [
        "http", "https", "ftp", "powershell", "cmd.exe", "/c", "Invoke-Expression",
        "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory", "GetProcAddress",
        "LoadLibrary", "RegSetValue", "IsDebuggerPresent", "WinExec"
    ]
    for kw in keywords:
        if kw.lower() in combined_text.lower():
            findings.add(kw)
            
    for regex in [r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", r"https?://[^\s'\"]+", r"\\\d{1,3}(?:\\.\\d{1,3}){3}"]:
        for match in re.findall(regex, combined_text):
            findings.add(match)

    return {
        "hashes": hashes,
        "entropy": entropy,
        "suspicious_strings": list(findings)
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
