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

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None
from app.schemas import UrlAnalysisResult
logger = logging.getLogger(__name__)

def _openai_generate_text(client, model: str, prompt: str, max_tokens: int = 220) -> str:
    if hasattr(client, "responses"):
        resp = client.responses.create(model=model, input=prompt, max_output_tokens=max_tokens)
        return (getattr(resp, "output_text", "") or "").strip()
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
    )
    return ((resp.choices[0].message.content if resp and resp.choices else "") or "").strip()


def _is_rate_limited(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    if "ratelimit" in name:
        return True
    status = getattr(exc, "status_code", None)
    if status == 429:
        return True
    return "429" in str(exc)


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
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return (
            "AI explanation unavailable because OPENAI_API_KEY is not configured. "
            "Current result is deterministic and evidence-based from integrated scanners."
        )
    try:
        client = OpenAI(api_key=api_key)
        prompt = (
            "You are a defensive cybersecurity analyst. Explain likely compromise path and remediation.\n"
            f"URL: {target_url}\n"
            f"Findings: {findings}\n"
            f"Vulnerabilities: {vulnerabilities}\n"
            f"Injection indicators: {injections}\n"
            "Output concise 4-6 sentences with evidence chain."
        )
        models = [os.getenv("OPENAI_MODEL", "").strip() or "gpt-4.1-mini", "gpt-4o-mini"]
        seen = set()
        last_exc: Exception | None = None
        for model in models:
            if model in seen:
                continue
            seen.add(model)
            for attempt in range(3):
                try:
                    text = _openai_generate_text(client, model, prompt, max_tokens=220)
                    if text:
                        return text
                except Exception as exc:
                    last_exc = exc
                    logger.debug("OpenAI URL explanation failed for %s model=%s attempt=%s: %s", target_url, model, attempt + 1, exc)
                    if _is_rate_limited(exc) and attempt < 2:
                        time.sleep(1.2 * (attempt + 1))
                        continue
                    break
        reason = f" ({type(last_exc).__name__})" if last_exc else ""
        if last_exc and _is_rate_limited(last_exc):
            return (
                "AI explanation service is temporarily rate-limited. "
                "Deterministic forensic findings remain available from integrated scanners. "
                "Retry in a few moments."
            )
        return (
            "AI explanation service could not be reached"
            f"{reason}. Deterministic forensic findings "
            "remain available from integrated scanners."
        )
    except Exception as exc:
        logger.debug("OpenAI URL explanation failed for %s: %s", target_url, exc)
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


def analyze_url(target_url: str) -> UrlAnalysisResult:
    normalized_url = _normalize_target_url(target_url)
    parsed = urlparse(normalized_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid URL. Use full URL format, e.g. https://example.com")

    domain = parsed.hostname or parsed.netloc
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    findings: list[str] = []
    malware_injection_findings: list[str] = []
    vulnerability_findings: list[str] = []
    score = 10

    if parsed.scheme != "https":
        score += 20
        findings.append("URL does not use HTTPS.")
    if any(k in normalized_url.lower() for k in ["login", "verify", "secure", "password", "signin"]):
        score += 12
        findings.append("Phishing keyword patterns detected in URL.")
    if any(k in query for k in ["redirect=", "url=", "next=", "target="]):
        score += 10
        findings.append("Suspicious redirect query parameters found.")
        vulnerability_findings.append("Possible open redirect exposure.")
    if any(x in query for x in ["%3cscript", "<script", "onerror=", "onload="]):
        score += 14
        vulnerability_findings.append("Possible reflected XSS payload pattern.")
    if ".php" in path and "id=" in query:
        score += 10
        vulnerability_findings.append("SQL injection probe-like URL structure.")
    if any(x in path for x in ["admin", "wp-admin", "phpmyadmin"]):
        score += 9
        vulnerability_findings.append("Possible exposed admin panel path.")
    if any(x in path for x in ["shell", "backdoor", "cmd"]):
        score += 14
        malware_injection_findings.append("Potential web-shell/backdoor naming pattern.")
    if any(x in path for x in [".js", ".zip", ".exe", ".scr"]):
        score += 10
        malware_injection_findings.append("Suspicious script or payload delivery path.")
    if "iframe" in query or "iframe" in path:
        score += 10
        malware_injection_findings.append("Potential hidden iframe injection signal.")

    ssl_info = _ssl_certificate_analysis(domain)
    rep = _domain_reputation(domain)
    ip_rep = _ip_reputation(domain)
    urlscan = _urlscan_lookup(normalized_url)
    urlscan_fresh = _urlscan_submit_and_poll(normalized_url)
    page_artifacts = _fetch_page_artifacts(normalized_url)
    zap = _zap_quick_assessment(normalized_url)

    if rep["blacklist_hit"]:
        score += 25
        findings.append("Domain appears on blacklist/reputation feeds.")
    if urlscan.get("available") and urlscan.get("verdict") is True:
        score += 20
        findings.append("URLScan indicates malicious verdict.")
    if urlscan_fresh.get("submitted") and urlscan_fresh.get("ready") and urlscan_fresh.get("verdict") is True:
        score += 18
        findings.append("Fresh URLScan submission returned malicious verdict.")
    if page_artifacts.get("iframe_count", 0) > 0:
        score += 8
        findings.append("Fetched page contains iframe elements.")
    if page_artifacts.get("hidden_iframe_count", 0) > 0:
        score += 10
        findings.append("Hidden iframe behavior detected in fetched content.")
    if page_artifacts.get("script_count", 0) > 15:
        score += 8
        findings.append("Fetched page contains high script density.")
    if page_artifacts.get("suspicious_script_patterns"):
        score += 12
        findings.append("Suspicious obfuscation or miner-like script patterns found.")
        malware_injection_findings.append("Script content matches obfuscation/miner signatures.")
    if page_artifacts.get("suspicious_form_count", 0) > 0:
        score += 9
        findings.append("Login-like forms with risky action handling were detected.")
    if not ssl_info["has_tls"]:
        score += 15
    elif ssl_info["status"] in {"Expired certificate", "Certificate expiring soon"}:
        score += 10

    score = max(0, min(score, 100))
    threat_level = "safe"
    if score >= 80:
        threat_level = "critical"
    elif score >= 60:
        threat_level = "high"
    elif score >= 35:
        threat_level = "suspicious"

    confidence = min(96, max(45, 55 + len(findings) * 6))
    if zap.get("enabled") and zap.get("available"):
        vulnerability_findings.append("OWASP ZAP alerts summary was included in this assessment.")
    explanation = _generate_url_ai_explanation(
        normalized_url, findings, vulnerability_findings, malware_injection_findings
    )
    malware_families = _malware_family_mapping(findings + malware_injection_findings)

    iocs = [{"type": "domain", "value": domain}, {"type": "url", "value": normalized_url}]
    try:
        iocs.append({"type": "ip", "value": socket.gethostbyname(domain)})
    except OSError as exc:
        logger.debug("IOC IP resolution failed for domain=%s: %s", domain, exc)
    for script_src in page_artifacts.get("external_script_samples", [])[:10]:
        iocs.append({"type": "script", "value": script_src})
    for suspicious_path in page_artifacts.get("suspicious_paths", [])[:10]:
        iocs.append({"type": "suspicious_path", "value": suspicious_path})
    for email in page_artifacts.get("emails", [])[:10]:
        iocs.append({"type": "email", "value": email})

    health_breakdown = {
        "ssl_security": 30 if not ssl_info["has_tls"] else 85 if ssl_info["status"] == "Certificate valid" else 55,
        "malware_presence": max(20, 100 - score),
        "vulnerability_exposure": max(20, 92 - int(score * 0.8)),
        "reputation": 30 if rep["blacklist_hit"] else 80,
        "content_integrity": max(20, 88 - int(score * 0.7)),
    }

    recs = [
        "Run this URL in a controlled sandbox browser before any user access.",
        "Correlate detected IOC domain/IP in DNS, proxy, and EDR telemetry.",
        "Block confirmed malicious domains/IPs at DNS and secure web gateway.",
    ]
    if threat_level in {"high", "critical"}:
        recs.append("Trigger incident response triage for potentially affected user endpoints.")

    website_compromise_indicators = []
    if page_artifacts.get("hidden_iframe_count", 0) > 0:
        website_compromise_indicators.append("Hidden iframe behavior suggests potential injected content.")
    if page_artifacts.get("suspicious_script_patterns"):
        website_compromise_indicators.append("Script obfuscation/miner patterns detected in page content.")
    if any("backdoor" in x.lower() or "shell" in x.lower() for x in page_artifacts.get("suspicious_paths", [])):
        website_compromise_indicators.append("Suspicious path signatures aligned with backdoor/web-shell artifacts.")
    if rep["blacklist_hit"]:
        website_compromise_indicators.append("Domain is flagged by one or more blacklist/reputation sources.")

    security_feedback = {
        "severity_level": threat_level,
        "confidence_score": confidence,
        "threat_explanation": explanation,
        "what_to_do_next": recs[:3],
        "audience_note": "This assessment is defensive and evidence-based; validate with incident response context before containment actions.",
    }

    return UrlAnalysisResult(
        input_url=normalized_url,
        domain=domain,
        risk_score=score,
        threat_level=threat_level,
        confidence=confidence,
        threat_explanation=explanation,
        findings=findings or ["No high-confidence malicious indicators from current checks."],
        malware_injection_findings=malware_injection_findings or ["No direct web injection pattern identified."],
        vulnerability_findings=vulnerability_findings or ["No high-confidence vulnerability signal identified."],
        suspicious_behaviors_detected=len(findings),
        iocs=iocs,
        website_compromise_indicators=website_compromise_indicators or ["No strong website compromise indicators were confirmed from current evidence."],
        security_feedback=security_feedback,
        page_artifacts=page_artifacts,
        threat_intel_mapping={
            "suspicious_domains": [domain],
            "ip_reputation": ip_rep,
            "malware_families": malware_families,
            "related_attack_infrastructure": [
                "Landing domain",
                "Potential redirect endpoint",
                "Potential payload location",
            ],
            "known_malicious_patterns": findings + malware_injection_findings + vulnerability_findings,
        },
        reputation_signals={
            "blacklist_status": "listed" if rep["blacklist_hit"] else "not_listed_or_unavailable",
            "blacklist_sources": rep["blacklist_sources"],
            "domain_reputation": rep["domain_reputation"],
            "urlscan": urlscan,
            "urlscan_fresh": urlscan_fresh,
            "zap": zap,
            "ssl_certificate_analysis": ssl_info,
            "provider_status": {
                "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
                "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
                "urlscan": bool(os.getenv("URLSCAN_API_KEY")),
                "phishtank": bool(os.getenv("PHISHTANK_API_KEY")),
            },
        },
        health_breakdown=health_breakdown,
        possible_attack_chain=[
            "Initial lure via suspicious URL delivery",
            "Victim redirection or scripted web interaction",
            "Credential theft or payload staging",
            "Persistence or monetization objective",
        ],
        recommendations=recs,
    )
