import logging
import os
from fastapi import APIRouter, File, UploadFile, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from cryptography.fernet import Fernet, InvalidToken
from app.services.file_scanner import analyze_file
from app.services.report_generator import create_pdf_report, create_url_pdf_report, create_log_pdf_report
from app.services.url_analyzer import analyze_url
from app.services.log_analyzer import analyze_log_text
from app.services.yara_scanner import yara_status
from app.services.memory_analyzer import volatility_status
from app.database.mongo import mongo_status
from app.database.repositories import (
    safe_insert,
    safe_list,
    safe_list_filtered,
    safe_get_by_id,
    save_watchlist_item,
    get_watchlist,
    save_alert,
    get_alerts,
)
from app.schemas import UrlAnalysisRequest, LogAnalysisRequest, MonitorAddRequest, ApiKeysUpdateRequest
from datetime import datetime
from app.security import require_api_key, enforce_rate_limit

router = APIRouter()
logger = logging.getLogger(__name__)
MONITOR_STATE = {"watchlist": [], "alerts": [], "last_checked": {}}
MONITOR_COOLDOWN_SECONDS = 300
MAX_WATCHLIST = 100


def _mask_secret(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= 4:
        return "*" * len(v)
    return ("*" * (len(v) - 4)) + v[-4:]


def _fernet() -> Fernet:
    key = os.getenv("SETTINGS_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("SETTINGS_ENCRYPTION_KEY is not configured.")
    return Fernet(key.encode("utf-8"))


def _encrypt_secret(value: str) -> str:
    if not value:
        return ""
    token = _fernet().encrypt(value.encode("utf-8"))
    return token.decode("utf-8")


def _decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        # Legacy plaintext fallback for pre-encryption records.
        return value


def _apply_runtime_provider_keys(doc: dict) -> None:
    """
    Keep scanner providers in sync with saved settings so backend analyzers
    can use keys immediately without a restart.
    """
    mappings = {
        "enc_virustotal_api_key": "VIRUSTOTAL_API_KEY",
        "enc_abuseipdb_api_key": "ABUSEIPDB_API_KEY",
        "enc_openai_api_key": "OPENAI_API_KEY",
        "enc_urlscan_api_key": "URLSCAN_API_KEY",
        "enc_phishtank_api_key": "PHISHTANK_API_KEY",
    }
    for enc_field, env_name in mappings.items():
        decrypted = _decrypt_secret(str(doc.get(enc_field, ""))).strip()
        if decrypted:
            os.environ[env_name] = decrypted


def _hydrate_runtime_keys_from_latest_settings() -> None:
    latest = safe_list("app_settings", limit=1)
    if not latest:
        return
    _apply_runtime_provider_keys(latest[0])


@router.post("/analyze-file")
async def analyze_file_endpoint(request: Request, file: UploadFile = File(...), _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    if not file.filename:
        raise HTTPException(status_code=400, detail="A valid file must be uploaded.")

    result = await analyze_file(file)
    safe_insert(
        "file_scans",
        {
            "scan_type": "file",
            "target": result.target,
            "severity": result.severity,
            "risk_score": result.risk_score,
            "result": result.model_dump(),
            "created_at": datetime.utcnow().isoformat() + "Z"
        },
    )
    return result


@router.post("/generate-report")
async def generate_report_endpoint(request: Request, file: UploadFile = File(...), _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    if not file.filename:
        raise HTTPException(status_code=400, detail="A valid file must be uploaded.")

    analysis = await analyze_file(file)
    safe_insert(
        "reports",
        {
            "report_type": "file",
            "filename": file.filename,
            "severity": analysis.severity,
            "result_summary": (analysis.ai_explanation or "")[:500],
            "created_at": datetime.utcnow().isoformat() + "Z",
        },
    )
    pdf_stream = create_pdf_report(analysis)
    headers = {
        "Content-Disposition": f"attachment; filename=ghosttrace_report_{file.filename}.pdf"
    }
    return StreamingResponse(pdf_stream, media_type="application/pdf", headers=headers)


@router.post("/analyze-url")
async def analyze_url_endpoint(request: Request, payload: UrlAnalysisRequest, _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    _hydrate_runtime_keys_from_latest_settings()
    try:
        result = analyze_url(payload.url)
        safe_insert(
            "url_scans",
            {
                "scan_type": "url",
                "target": result.target,
                "severity": result.severity,
                "risk_score": result.risk_score,
                "result": result.model_dump(),
                "created_at": datetime.utcnow().isoformat() + "Z"
            },
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/generate-url-report")
async def generate_url_report_endpoint(request: Request, payload: UrlAnalysisRequest, _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    _hydrate_runtime_keys_from_latest_settings()
    result = analyze_url(payload.url)
    safe_insert(
        "reports",
        {
            "report_type": "url",
            "url": payload.url,
            "target": result.target,
            "severity": result.severity,
            "result_summary": (result.ai_explanation or "")[:500],
            "created_at": datetime.utcnow().isoformat() + "Z",
        },
    )
    pdf_stream = create_url_pdf_report(result)
    headers = {"Content-Disposition": "attachment; filename=ghosttrace_url_report.pdf"}
    return StreamingResponse(pdf_stream, media_type="application/pdf", headers=headers)


@router.post("/generate-log-report")
async def generate_log_report_endpoint(request: Request, payload: LogAnalysisRequest, _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    _hydrate_runtime_keys_from_latest_settings()
    result = analyze_log_text(payload.log_text)
    safe_insert(
        "reports",
        {
            "report_type": "log",
            "severity": result.severity,
            "result_summary": (result.ai_explanation or "")[:500],
            "created_at": datetime.utcnow().isoformat() + "Z",
        },
    )
    pdf_stream = create_log_pdf_report(result)
    headers = {"Content-Disposition": "attachment; filename=ghosttrace_log_report.pdf"}
    return StreamingResponse(pdf_stream, media_type="application/pdf", headers=headers)


@router.post("/analyze-log")
async def analyze_log_endpoint(request: Request, payload: LogAnalysisRequest, _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    _hydrate_runtime_keys_from_latest_settings()
    result = analyze_log_text(payload.log_text)
    safe_insert(
        "log_scans",
        {
            "scan_type": "log",
            "target": result.target,
            "severity": result.severity,
            "risk_score": result.risk_score,
            "result": result.model_dump(),
            "created_at": datetime.utcnow().isoformat() + "Z"
        },
    )
    return result


@router.post("/monitor/add")
async def monitor_add_endpoint(request: Request, payload: MonitorAddRequest, _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    if len(MONITOR_STATE["watchlist"]) >= MAX_WATCHLIST and payload.url not in MONITOR_STATE["watchlist"]:
        raise HTTPException(status_code=400, detail="Watchlist limit reached.")
    if payload.url not in MONITOR_STATE["watchlist"]:
        MONITOR_STATE["watchlist"].append(payload.url)
    save_watchlist_item(payload.url)
    return {"watchlist": MONITOR_STATE["watchlist"]}


@router.post("/monitor/check")
async def monitor_check_endpoint(request: Request, _: None = Depends(require_api_key)):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    persisted = get_watchlist()
    for url in persisted:
        if url not in MONITOR_STATE["watchlist"]:
            MONITOR_STATE["watchlist"].append(url)
    now = datetime.utcnow()
    for url in MONITOR_STATE["watchlist"]:
        try:
            last_checked = MONITOR_STATE["last_checked"].get(url)
            if last_checked:
                last_dt = datetime.fromisoformat(last_checked.replace("Z", ""))
                if (now - last_dt).total_seconds() < MONITOR_COOLDOWN_SECONDS:
                    continue
            result = analyze_url(url)
            MONITOR_STATE["last_checked"][url] = now.isoformat() + "Z"
            if result.threat_level in {"high", "critical"}:
                MONITOR_STATE["alerts"].append(
                    {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "url": url,
                        "threat_level": result.threat_level,
                        "message": "Monitoring check detected elevated risk.",
                        "risk_score": result.risk_score,
                    }
                )
                save_alert(MONITOR_STATE["alerts"][-1])
        except Exception as exc:
            logger.warning("Monitor check failed for %s: %s", url, exc)
            continue
    MONITOR_STATE["alerts"] = MONITOR_STATE["alerts"][-100:]
    return {"status": "ok", "watchlist_count": len(MONITOR_STATE["watchlist"])}


@router.get("/monitor/status")
async def monitor_status_endpoint(_: None = Depends(require_api_key)):
    return {"watchlist": get_watchlist(), "alerts": get_alerts(limit=100), "last_checked": MONITOR_STATE["last_checked"]}


@router.get("/security-libs-status")
async def security_libs_status_endpoint(_: None = Depends(require_api_key)):
    return {
        "yara": yara_status(),
        "beautifulsoup": {"available": True, "message": "Integrated in URL content pipeline."},
        "volatility3": volatility_status(),
        "owasp_zap": {
            "configured": bool(__import__("os").getenv("ZAP_API_URL")),
            "message": "Set ZAP_API_URL (and optional ZAP_API_KEY) to enable live ZAP checks.",
        },
        "mongodb": mongo_status(),
        "provider_status": {
            "virustotal": bool(__import__("os").getenv("VIRUSTOTAL_API_KEY")),
            "abuseipdb": bool(__import__("os").getenv("ABUSEIPDB_API_KEY")),
            "phishtank": bool(__import__("os").getenv("PHISHTANK_API_KEY")),
            "urlscan": bool(__import__("os").getenv("URLSCAN_API_KEY")),
            "openai": bool(__import__("os").getenv("OPENAI_API_KEY")),
        },
    }


@router.get("/history/files")
async def history_files_endpoint(
    _: None = Depends(require_api_key),
    limit: int = 50,
    severity: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    return {
        "items": safe_list_filtered(
            "file_scans",
            limit=limit,
            severity=severity,
            q=q,
            date_from=date_from,
            date_to=date_to,
        )
    }


@router.get("/history/urls")
async def history_urls_endpoint(
    _: None = Depends(require_api_key),
    limit: int = 50,
    severity: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    return {
        "items": safe_list_filtered(
            "url_scans",
            limit=limit,
            severity=severity,
            q=q,
            date_from=date_from,
            date_to=date_to,
        )
    }


@router.get("/history/logs")
async def history_logs_endpoint(
    _: None = Depends(require_api_key),
    limit: int = 50,
    severity: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    return {
        "items": safe_list_filtered(
            "log_scans",
            limit=limit,
            severity=severity,
            q=q,
            date_from=date_from,
            date_to=date_to,
        )
    }


@router.get("/reports")
async def reports_history_endpoint(limit: int = 50, _: None = Depends(require_api_key)):
    return {"items": safe_list("reports", limit=limit)}


@router.post("/settings/api-keys")
async def save_api_keys_endpoint(payload: ApiKeysUpdateRequest, _: None = Depends(require_api_key)):
    try:
        encrypted_doc = {
            "kind": "api_keys",
            "enc_ghosttrace_api_key": _encrypt_secret(payload.ghosttrace_api_key or ""),
            "enc_virustotal_api_key": _encrypt_secret(payload.virustotal_api_key or ""),
            "enc_abuseipdb_api_key": _encrypt_secret(payload.abuseipdb_api_key or ""),
            "enc_openai_api_key": _encrypt_secret(payload.openai_api_key or ""),
            "enc_urlscan_api_key": _encrypt_secret(payload.urlscan_api_key or ""),
            "enc_phishtank_api_key": _encrypt_secret(payload.phishtank_api_key or ""),
        }
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    doc = {
        **encrypted_doc,
        "enc_version": 1,
    }
    _apply_runtime_provider_keys(doc)
    saved = safe_insert("app_settings", doc)
    return {"saved": bool(saved.get("saved")), "id": saved.get("id")}


@router.get("/settings/api-keys")
async def get_api_keys_endpoint(_: None = Depends(require_api_key)):
    latest = safe_list("app_settings", limit=1)
    if not latest:
        return {
            "configured": {},
            "masked": {},
            "source": "none",
        }
    doc = latest[0]
    keys = {
        "ghosttrace_api_key": _decrypt_secret(str(doc.get("enc_ghosttrace_api_key", doc.get("ghosttrace_api_key", "")))),
        "virustotal_api_key": _decrypt_secret(str(doc.get("enc_virustotal_api_key", doc.get("virustotal_api_key", "")))),
        "abuseipdb_api_key": _decrypt_secret(str(doc.get("enc_abuseipdb_api_key", doc.get("abuseipdb_api_key", "")))),
        "openai_api_key": _decrypt_secret(str(doc.get("enc_openai_api_key", doc.get("openai_api_key", "")))),
        "urlscan_api_key": _decrypt_secret(str(doc.get("enc_urlscan_api_key", doc.get("urlscan_api_key", "")))),
        "phishtank_api_key": _decrypt_secret(str(doc.get("enc_phishtank_api_key", doc.get("phishtank_api_key", "")))),
    }
    return {
        "configured": {k: bool(v) for k, v in keys.items()},
        "masked": {k: _mask_secret(str(v)) for k, v in keys.items()},
        "source": "database",
    }


@router.get("/history/files/{item_id}")
async def history_file_detail_endpoint(item_id: str, _: None = Depends(require_api_key)):
    item = safe_get_by_id("file_scans", item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Not found")
    return item


@router.get("/history/urls/{item_id}")
async def history_url_detail_endpoint(item_id: str, _: None = Depends(require_api_key)):
    item = safe_get_by_id("url_scans", item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Not found")
    return item


@router.get("/history/logs/{item_id}")
async def history_log_detail_endpoint(item_id: str, _: None = Depends(require_api_key)):
    item = safe_get_by_id("log_scans", item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Not found")
    return item
