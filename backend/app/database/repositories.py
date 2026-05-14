from datetime import datetime, timezone
from typing import Any
import logging

from app.database.mongo import get_mongo_client
try:
    from bson import ObjectId
except Exception:  # pragma: no cover
    ObjectId = None  # type: ignore


DB_NAME = "ghosttrace"
logger = logging.getLogger(__name__)


def _serialize_doc(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    if "_id" in out:
        out["id"] = str(out.pop("_id"))
    return out


def _collection(name: str):
    client = get_mongo_client()
    return client[DB_NAME][name]


def safe_insert(collection: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = dict(payload)
    body.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    try:
        col = _collection(collection)
        res = col.insert_one(body)
        return {"saved": True, "id": str(res.inserted_id)}
    except Exception as exc:
        return {"saved": False, "error": str(exc)}


def safe_list(collection: str, limit: int = 50) -> list[dict[str, Any]]:
    try:
        col = _collection(collection)
        docs = list(col.find().sort("created_at", -1).limit(limit))
        return [_serialize_doc(d) for d in docs]
    except Exception as exc:
        logger.warning("safe_list failed for collection=%s: %s", collection, exc)
        return []


def safe_list_filtered(
    collection: str,
    limit: int = 50,
    severity: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    try:
        col = _collection(collection)
        query: dict[str, Any] = {}
        if severity:
            query["severity"] = severity

        if q:
            query["$or"] = [
                {"filename": {"$regex": q, "$options": "i"}},
                {"url": {"$regex": q, "$options": "i"}},
                {"result_summary": {"$regex": q, "$options": "i"}},
            ]

        if date_from or date_to:
            created_at_filter: dict[str, Any] = {}
            if date_from:
                created_at_filter["$gte"] = date_from
            if date_to:
                created_at_filter["$lte"] = date_to
            query["created_at"] = created_at_filter

        docs = list(col.find(query).sort("created_at", -1).limit(limit))
        return [_serialize_doc(d) for d in docs]
    except Exception as exc:
        logger.warning("safe_list_filtered failed for collection=%s: %s", collection, exc)
        return []


def safe_get_by_id(collection: str, item_id: str) -> dict[str, Any] | None:
    try:
        if ObjectId is None:
            return None
        col = _collection(collection)
        doc = col.find_one({"_id": ObjectId(item_id)})
        return _serialize_doc(doc) if doc else None
    except Exception as exc:
        logger.warning("safe_get_by_id failed for collection=%s item_id=%s: %s", collection, item_id, exc)
        return None


def save_watchlist_item(url: str) -> dict[str, Any]:
    existing = safe_list_filtered("monitor_watchlist", limit=1, q=url)
    if any((x.get("url") == url) for x in existing):
        return {"saved": True, "duplicate": True}
    return safe_insert("monitor_watchlist", {"url": url})


def get_watchlist() -> list[str]:
    docs = safe_list("monitor_watchlist", limit=500)
    return [d.get("url") for d in docs if d.get("url")]


def save_alert(alert: dict[str, Any]) -> dict[str, Any]:
    return safe_insert("monitor_alerts", alert)


def get_alerts(limit: int = 200) -> list[dict[str, Any]]:
    return safe_list("monitor_alerts", limit=limit)
