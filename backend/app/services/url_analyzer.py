import json
import os
import re
import socket
import ssl
import time
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None

from app.services.ai_engine import get_mitre_mapping
from app.services.llm_fallback import generate_with_fallback
from app.schemas import UrlAnalysisResult, UnifiedInvestigationResult
logger = logging.getLogger(__name__)

def _safe_get_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    req = Request(url, headers=headers or {})
    try:
        with urlopen(req, timeout=6) as resp:  # nosec B310 - defensive intel lookups only
            data = resp.read().decode("utf-8", errors="ignore")
            return json.loads(data)
    except (URLError, TimeoutError, ValueError):
        return None


def _safe_post_json(
    url: str, payload: dict[str, Any], headers: dict[str, str] | None = None
) -> dict[str, Any] | None:
    body = json.dumps(payload).encode("utf-8")
    merged_headers = {"Content-Type": "application/json", **(headers or {})}
    req = Request(url, data=body, headers=merged_headers, method="POST")
    try:
        with urlopen(req, timeout=10) as resp:  # nosec B310 - defensive intel requests
            data = resp.read().decode("utf-8", errors="ignore")
            return json.loads(data)
    except (URLError, TimeoutError, ValueError):
        return None


def _fetch_page_artifacts(target_url: str) -> dict[str, Any]:
    headers = {"User-Agent": "GhostTrace-Defensive-Analyzer/1.0"}
    req = Request(target_url, headers=headers)
    try:
        with urlopen(req, timeout=8) as resp:  # nosec B310 - defensive scan fetch
            html = resp.read().decode("utf-8", errors="ignore")
    except Exception as exc:
        logger.debug("Failed to fetch page artifacts for %s: %s", target_url, exc)
        return {
            "available": False,
            "title": None,
            "script_count": 0,
            "iframe_count": 0,
            "external_script_samples": [],
            "html_preview": "",
        }

    if BeautifulSoup is None:
        suspicious_paths = re.findall(r"/[A-Za-z0-9_\-./]*(?:admin|login|shell|backdoor|upload|wp-admin)[A-Za-z0-9_\-./]*", html, flags=re.IGNORECASE)
        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html)
        return {
            "available": True,
            "title": None,
            "script_count": len(re.findall(r"<script\b", html, flags=re.IGNORECASE)),
            "iframe_count": len(re.findall(r"<iframe\b", html, flags=re.IGNORECASE)),
            "hidden_iframe_count": 0,
            "suspicious_form_count": 0,
            "suspicious_script_patterns": [],
            "external_script_samples": re.findall(r"<script[^>]*src=[\"']([^\"']+)[\"'][^>]*>", html, flags=re.IGNORECASE)[:8],
            "suspicious_paths": sorted(set(suspicious_paths))[:20],
            "emails": sorted(set(emails))[:20],
            "html_preview": re.sub(r"\s+", " ", html[:1200]).strip(),
        }

    soup = BeautifulSoup(html, "html.parser")
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    inline_scripts = [s.get_text(strip=False) for s in soup.find_all("script") if not s.get("src")]
    iframes = soup.find_all("iframe")
    suspicious_script_patterns = []
    script_blob = " ".join(inline_scripts).lower()
    for pattern in ["eval(", "fromcharcode", "atob(", "webassembly", "coinhive", "cryptonight"]:
        if pattern in script_blob:
            suspicious_script_patterns.append(pattern)

    hidden_iframe_count = 0
    for iframe in iframes:
        style = (iframe.get("style") or "").lower()
        width = (iframe.get("width") or "").strip()
        height = (iframe.get("height") or "").strip()
        if "display:none" in style or width in {"0", "1"} or height in {"0", "1"}:
            hidden_iframe_count += 1

    forms = soup.find_all("form")
    suspicious_forms = 0
    for form in forms:
        action = (form.get("action") or "").lower()
        input_types = {str(i.get("type", "")).lower() for i in form.find_all("input")}
        if "password" in input_types and (action.startswith("http://") or action == ""):
            suspicious_forms += 1

    title_tag = soup.find("title")
    preview = re.sub(r"\s+", " ", html[:1200]).strip()
    return {
        "available": True,
        "title": title_tag.get_text(strip=True) if title_tag else None,
        "script_count": len(soup.find_all("script")),
        "iframe_count": len(iframes),
        "hidden_iframe_count": hidden_iframe_count,
        "suspicious_form_count": suspicious_forms,
        "suspicious_script_patterns": suspicious_script_patterns,
        "external_script_samples": scripts[:8],
        "suspicious_paths": sorted(
            set(
                re.findall(
                    r"/[A-Za-z0-9_\-./]*(?:admin|login|shell|backdoor|upload|wp-admin)[A-Za-z0-9_\-./]*",
                    html,
                    flags=re.IGNORECASE,
                )
            )
        )[:20],
        "emails": sorted(
            set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html))
        )[:20],
        "html_preview": preview,
    }


def _ssl_certificate_analysis(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "has_tls": False,
        "issuer": "unknown",
        "subject": "unknown",
        "not_before": None,
        "not_after": None,
        "days_to_expiry": None,
        "status": "Unavailable",
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                result["has_tls"] = True
                result["issuer"] = ", ".join("=".join(x) for tup in cert.get("issuer", []) for x in tup)
                result["subject"] = ", ".join("=".join(x) for tup in cert.get("subject", []) for x in tup)
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")
                if cert.get("notAfter"):
                    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(tz=timezone.utc)
                    result["days_to_expiry"] = (expiry - now).days
                    if result["days_to_expiry"] < 0:
                        result["status"] = "Expired certificate"
                    elif result["days_to_expiry"] < 15:
                        result["status"] = "Certificate expiring soon"
                    else:
                        result["status"] = "Certificate valid"
                else:
                    result["status"] = "Certificate present (expiry unknown)"
    except Exception as exc:
        logger.debug("TLS certificate analysis failed for %s: %s", domain, exc)
        result["status"] = "TLS handshake failed or certificate unavailable"
    return result


def _domain_reputation(domain: str) -> dict[str, Any]:
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    phishing_key = os.getenv("PHISHTANK_API_KEY")
    local_blacklist = {"malware.test", "phishing.test", "evil.example"}

    reputation = {
        "blacklist_hit": domain in local_blacklist,
        "blacklist_sources": ["local_static_list"] if domain in local_blacklist else [],
        "domain_reputation": "unknown",
        "vt_malicious": None,
        "phishtank_in_database": None,
    }

    if vt_key:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{quote_plus(domain)}"
        vt_data = _safe_get_json(vt_url, headers={"x-apikey": vt_key})
        if vt_data:
            stats = (
                vt_data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            reputation["vt_malicious"] = malicious
            if malicious > 0 or suspicious > 0:
                reputation["blacklist_hit"] = True
                reputation["blacklist_sources"].append("virustotal")

    if phishing_key:
        pt_url = (
            "https://checkurl.phishtank.com/checkurl/"
            f"?url={quote_plus('http://' + domain)}&format=json&app_key={quote_plus(phishing_key)}"
        )
        pt_data = _safe_get_json(pt_url)
        if pt_data:
            in_db = bool(pt_data.get("results", {}).get("in_database", False))
            valid = bool(pt_data.get("results", {}).get("valid", False))
            reputation["phishtank_in_database"] = in_db
            if in_db and valid:
                reputation["blacklist_hit"] = True
                reputation["blacklist_sources"].append("phishtank")

    if reputation["blacklist_hit"]:
        reputation["domain_reputation"] = "malicious_or_suspicious"
    elif vt_key:
        reputation["domain_reputation"] = "likely_clean_or_unclassified"

    return reputation


def _ip_reputation(domain: str) -> str:
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    try:
        ip = socket.gethostbyname(domain)
    except Exception as exc:
        logger.debug("DNS resolution failed for domain=%s: %s", domain, exc)
        return "DNS resolution failed"

    if not abuse_key:
        return f"Resolved IP {ip}; AbuseIPDB key missing for deep reputation lookup."

    lookup = _safe_get_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote_plus(ip)}&maxAgeInDays=90",
        headers={"Key": abuse_key, "Accept": "application/json"},
    )
    if not lookup or "data" not in lookup:
        return f"Resolved IP {ip}; AbuseIPDB lookup unavailable."

    score = lookup["data"].get("abuseConfidenceScore", 0)
    return f"Resolved IP {ip}; AbuseIPDB confidence score {score}/100."


def _malware_family_mapping(findings: list[str]) -> list[str]:
    text = " ".join(findings).lower()
    families = []
    if "login" in text or "credential" in text or "phishing" in text:
        families.append("Phishing Kit / Credential Harvester")
    if "iframe" in text or "script" in text:
        families.append("Web Inject / Malvertising Script")
    if "redirect" in text:
        families.append("Traffic Redirector")
    if "shell" in text or "backdoor" in text:
        families.append("Web Shell Pattern")
    return families or ["No high-confidence malware family attribution"]


def _urlscan_lookup(target_url: str) -> dict[str, Any]:
    key = os.getenv("URLSCAN_API_KEY")
    if not key:
        return {"available": False, "verdict": "URLScan key missing", "tags": []}
    data = _safe_get_json(
        f"https://urlscan.io/api/v1/search/?q=page.url:{quote_plus(target_url)}",
        headers={"API-Key": key},
    )
    if not data:
        return {"available": False, "verdict": "URLScan lookup unavailable", "tags": []}

    results = data.get("results", [])
    if not results:
        return {"available": True, "verdict": "No URLScan history found", "tags": []}

    top = results[0]
    verdicts = top.get("verdicts", {})
    overall = verdicts.get("overall", {})
    tags = top.get("page", {}).get("tags", [])
    return {
        "available": True,
        "verdict": overall.get("malicious", False),
        "score": overall.get("score"),
        "tags": tags,
    }


def _urlscan_submit_and_poll(target_url: str) -> dict[str, Any]:
    key = os.getenv("URLSCAN_API_KEY")
    if not key:
        return {"submitted": False, "message": "URLScan key missing"}
    submit = _safe_post_json(
        "https://urlscan.io/api/v1/scan/",
        {"url": target_url, "visibility": "unlisted"},
        headers={"API-Key": key},
    )
    if not submit or "uuid" not in submit:
        return {"submitted": False, "message": "URLScan submission failed"}

    uuid = submit["uuid"]
    api = f"https://urlscan.io/api/v1/result/{uuid}/"
    for _ in range(6):
        result = _safe_get_json(api, headers={"API-Key": key})
        if result:
            verdict = (
                result.get("verdicts", {})
                .get("overall", {})
                .get("malicious", False)
            )
            score = (
                result.get("verdicts", {})
                .get("overall", {})
                .get("score")
            )
            tags = result.get("page", {}).get("tags", [])
            return {
                "submitted": True,
                "ready": True,
                "uuid": uuid,
                "verdict": verdict,
                "score": score,
                "tags": tags,
            }
        time.sleep(2)
    return {"submitted": True, "ready": False, "uuid": uuid}


def _zap_quick_assessment(target_url: str) -> dict[str, Any]:
    zap_base = os.getenv("ZAP_API_URL")
    zap_key = os.getenv("ZAP_API_KEY")
    if not zap_base:
        return {"enabled": False, "message": "ZAP not configured"}

    query = f"{zap_base.rstrip('/')}/JSON/core/view/alertsSummary/?baseurl={quote_plus(target_url)}"
    if zap_key:
        query += f"&apikey={quote_plus(zap_key)}"
    data = _safe_get_json(query)
    if not data:
        return {"enabled": True, "available": False, "message": "ZAP unavailable"}
    return {"enabled": True, "available": True, "alerts_summary": data.get("alertsSummary", {})}


def _generate_url_ai_explanation(
    target_url: str, findings: list[str], vulnerabilities: list[str], injections: list[str]
) -> str:
    if not os.getenv("OPENAI_API_KEY", "").strip() and not os.getenv("GROQ_API_KEY", "").strip():
        return (
            "AI explanation unavailable because OPENAI_API_KEY is not configured. "
            "Current result is deterministic and evidence-based from integrated scanners."
        )
    prompt = (
        "You are a defensive cybersecurity analyst. Explain likely compromise path and remediation.\n"
        f"URL: {target_url}\n"
        f"Findings: {findings}\n"
        f"Vulnerabilities: {vulnerabilities}\n"
        f"Injection indicators: {injections}\n"
        "Output concise 4-6 sentences with evidence chain."
    )
    text = generate_with_fallback(prompt, max_tokens=220, primary_model="gpt-4.1-mini")
    if text:
        return text
    return (
        "AI explanation service could not be reached. Deterministic forensic findings "
        "remain available from integrated scanners."
    )


def _normalize_target_url(target_url: str) -> str:
    candidate = (target_url or "").strip()
    if not candidate:
        raise ValueError("URL is required.")
    if " " in candidate:
        raise ValueError("Invalid URL. Spaces are not allowed.")
    raw = candidate
    if "://" not in candidate:
        # Reject malformed host-like strings such as "not-a-url"
        if "." not in candidate and candidate.lower() != "localhost":
            raise ValueError("Invalid URL. Use full URL format, e.g. https://example.com")
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid URL. Use full URL format, e.g. https://example.com")
    if "." not in parsed.netloc and parsed.hostname not in {"localhost", None} and raw == parsed.netloc:
        raise ValueError("Invalid URL. Use full URL format, e.g. https://example.com")
    return candidate


from app.schemas import UrlAnalysisResult, UnifiedInvestigationResult
logger = logging.getLogger(__name__)

# ... (internal functions stay the same, I'll only replace analyze_url)

def analyze_url(target_url: str) -> UnifiedInvestigationResult:
    normalized_url = _normalize_target_url(target_url)
    parsed = urlparse(normalized_url)
    
    domain = parsed.hostname or parsed.netloc
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    findings: list[str] = []
    malware_injection_findings: list[str] = []
    vulnerability_findings: list[str] = []
    score = 10

    # ── Protocol & Keywords ──
    if parsed.scheme != "https":
        score += 20
        findings.append("URL does not use HTTPS; traffic is exposed to interception.")
    if any(k in normalized_url.lower() for k in ["login", "verify", "secure", "password", "signin", "paypal", "bank"]):
        score += 15
        findings.append("Phishing-typical keywords or brand impersonation detected in URL string.")
        
    # ── Vulnerability Patterns ──
    if any(k in query for k in ["redirect=", "url=", "next=", "target=", "dest="]):
        score += 15
        vulnerability_findings.append("Potential open-redirect vulnerability in query parameters.")
    if any(x in query or x in path for x in ["<script", "%3cscript", "javascript:", "onload=", "onerror="]):
        score += 20
        vulnerability_findings.append("XSS (Cross-Site Scripting) payload pattern detected in URL.")
    if any(x in query for x in ["'", " union ", "--", "select ", "drop ", "table "]):
        score += 20
        vulnerability_findings.append("SQL Injection probe pattern detected in query string.")
        
    # ── Path-based Threats ──
    if any(x in path for x in ["admin", "wp-admin", "phpmyadmin", "config", "setup", ".git", ".env"]):
        score += 15
        vulnerability_findings.append("Exposed sensitive path or management interface detected.")
    if any(x in path for x in ["shell", "backdoor", "cmd", "exec", "upload"]):
        score += 20
        malware_injection_findings.append("Path signature aligns with web-shell or backdoor artifacts.")

    # ── Enrichment & Page Analysis ──
    ssl_info = _ssl_certificate_analysis(domain)
    rep = _domain_reputation(domain)
    ip_rep = _ip_reputation(domain)
    urlscan = _urlscan_lookup(normalized_url)
    urlscan_live: dict[str, Any] = {"submitted": False}
    if os.getenv("URLSCAN_API_KEY", "").strip():
        if not urlscan.get("available") or urlscan.get("verdict") in {None, False}:
            urlscan_live = _urlscan_submit_and_poll(normalized_url)
    page_artifacts = _fetch_page_artifacts(normalized_url)

    if rep["blacklist_hit"]:
        score += 30
        findings.append("Domain is explicitly flagged on global threat reputation feeds.")
    if urlscan.get("available") and urlscan.get("verdict") is True:
        score += 25
        findings.append("URLScan.io reputation engine returned a confirmed malicious verdict.")
    if urlscan_live.get("ready") and urlscan_live.get("verdict") is True:
        score += 25
        findings.append("Live URLScan submission returned a confirmed malicious verdict.")
    
    if page_artifacts.get("hidden_iframe_count", 0) > 0:
        score += 15
        malware_injection_findings.append("Hidden iframes detected; common technique for drive-by downloads.")
    if page_artifacts.get("suspicious_script_patterns"):
        score += 20
        malware_injection_findings.append("Obfuscated or malicious JavaScript patterns detected in page content.")
    if page_artifacts.get("suspicious_form_count", 0) > 0:
        score += 15
        findings.append("Suspicious credential harvesting form detected over insecure connection.")

    score = min(score, 100)
    threat_level = "safe"
    if score >= 80:
        threat_level = "critical"
    elif score >= 60:
        threat_level = "high"
    elif score >= 35:
        threat_level = "medium"
    else:
        threat_level = "low"
        if score < 15: threat_level = "clean"

    explanation = _generate_url_ai_explanation(
        normalized_url, findings, vulnerability_findings, malware_injection_findings
    )

    # ── Standardizing IOCs ──
    iocs = [{"type": "domain", "value": domain}, {"type": "url", "value": normalized_url}]
    try:
        ip = socket.gethostbyname(domain)
        iocs.append({"type": "ip", "value": ip})
    except: pass
    
    for script in page_artifacts.get("external_script_samples", [])[:5]:
        iocs.append({"type": "script", "value": script})

    # ── Timeline Construction ──
    timeline = [
        {"stage": "DNS/SSL Audit", "details": f"Analyzed {domain}. {ssl_info['status']}.", "sev": "low" if ssl_info['has_tls'] else "medium"},
    ]
    if rep["blacklist_hit"] or (urlscan.get("available") and urlscan.get("verdict")):
        timeline.append({"stage": "Reputation Check", "details": "Negative reputation found in global threat feeds.", "sev": "high"})
    if urlscan_live.get("submitted"):
        timeline.append({
            "stage": "Live Sandbox Correlation",
            "details": "Submitted URL to URLScan for real-time verdict and artifact enrichment.",
            "sev": "medium",
        })
    
    if findings or vulnerability_findings or malware_injection_findings:
        timeline.append({"stage": "Content Analysis", "details": f"Found {len(findings)+len(vulnerability_findings)+len(malware_injection_findings)} suspicious indicators in URL and HTML.", "sev": "high" if score > 60 else "medium"})
        
    timeline.append({"stage": "AI Synthesis", "details": "Attack reconstruction and behavior analysis completed.", "sev": "low"})

    return UnifiedInvestigationResult(
        target=normalized_url,
        type="url",
        risk_score=score,
        severity=threat_level,
        confidence=min(98, max(40, 50 + len(findings)*8)),
        iocs=iocs,
        timeline=timeline,
        ai_explanation=explanation,
        recommendations=[
            "Do not visit this URL in a standard browser.",
            "Block this domain at the perimeter firewall/web gateway.",
            "Verify if any internal users have visited this URL via proxy logs."
        ],
        mitre_mapping=get_mitre_mapping(findings + vulnerability_findings + malware_injection_findings),
        health_breakdown={
            "ssl": 100 if ssl_info["has_tls"] else 0,
            "reputation": 0 if rep["blacklist_hit"] else 100,
            "malware": max(0, 100 - (len(malware_injection_findings) * 30)),
            "vulnerability": max(0, 100 - (len(vulnerability_findings) * 25))
        },
        raw_artifacts={
            "domain": domain,
            "ip_reputation": ip_rep,
            "ssl_info": ssl_info,
            "page_artifacts": page_artifacts,
            "urlscan": urlscan,
            "urlscan_live": urlscan_live,
        },
        evidence=findings + vulnerability_findings + malware_injection_findings
    )
