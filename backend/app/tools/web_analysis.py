import os
import json
from urllib.request import Request, urlopen
from urllib.error import URLError
from typing import Any

def check_virustotal_hash(sha256_hash: str) -> dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY missing"}

    req = Request(
        f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
        headers={"x-apikey": api_key},
    )
    try:
        with urlopen(req, timeout=8) as resp:  # nosec B310
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

def analyze_url_basic(url: str) -> dict[str, Any]:
    # A basic enrichment placeholder
    return {
        "url": url,
        "suspicious": "http://" in url or len(url) > 100,
        "domain": url.split("/")[2] if "/" in url and len(url.split("/")) > 2 else "unknown"
    }
