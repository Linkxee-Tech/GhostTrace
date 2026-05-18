from datetime import datetime, timezone
from typing import Any
import logging
import uuid
import re

from app.database.mongo import get_mongo_client
try:
    from bson import ObjectId
except Exception:  # pragma: no cover
    ObjectId = None  # type: ignore


DB_NAME = "ghosttrace"
logger = logging.getLogger(__name__)

# Global in-memory fallback storage
_in_memory_db: dict[str, list[dict[str, Any]]] = {}
_mongo_offline = False


def _serialize_doc(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    if "_id" in out:
        out["id"] = str(out.pop("_id"))
    return out


def _collection(name: str):
    global _mongo_offline
    if _mongo_offline:
        return None
    try:
        client = get_mongo_client()
        return client[DB_NAME][name]
    except Exception as exc:
        logger.warning("MongoDB initialization failed, falling back to in-memory: %s", exc)
        _mongo_offline = True
        return None


def safe_insert(collection: str, payload: dict[str, Any]) -> dict[str, Any]:
    global _mongo_offline
    body = dict(payload)
    body.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    
    if not _mongo_offline:
        try:
            col = _collection(collection)
            if col is not None:
                res = col.insert_one(body)
                return {"saved": True, "id": str(res.inserted_id)}
        except Exception as exc:
            logger.warning("safe_insert failed for MongoDB, falling back to in-memory: %s", exc)
            _mongo_offline = True

    # In-memory saving fallback
    if collection not in _in_memory_db:
        _in_memory_db[collection] = []
    
    doc_id = str(uuid.uuid4())
    body["id"] = doc_id
    _in_memory_db[collection].append(body)
    return {"saved": True, "id": doc_id, "fallback": True}


def safe_list(collection: str, limit: int = 50) -> list[dict[str, Any]]:
    global _mongo_offline
    if not _mongo_offline:
        try:
            col = _collection(collection)
            if col is not None:
                docs = list(col.find().sort("created_at", -1).limit(limit))
                return [_serialize_doc(d) for d in docs]
        except Exception as exc:
            logger.warning("safe_list failed for MongoDB, falling back to in-memory: %s", exc)
            _mongo_offline = True

    # In-memory listing fallback
    items = _in_memory_db.get(collection, [])
    sorted_items = sorted(items, key=lambda x: x.get("created_at", ""), reverse=True)
    return sorted_items[:limit]


def safe_list_filtered(
    collection: str,
    limit: int = 50,
    severity: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    global _mongo_offline
    if not _mongo_offline:
        try:
            col = _collection(collection)
            if col is not None:
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
            logger.warning("safe_list_filtered failed for MongoDB, falling back to in-memory: %s", exc)
            _mongo_offline = True

    # In-memory filtered listing fallback
    items = _in_memory_db.get(collection, [])
    filtered = []
    for item in items:
        if severity and item.get("severity") != severity:
            continue
        if q:
            match = False
            for field in ["filename", "url", "result_summary"]:
                val = str(item.get(field, ""))
                if re.search(q, val, re.IGNORECASE):
                    match = True
                    break
            if not match:
                continue
        if date_from and item.get("created_at", "") < date_from:
            continue
        if date_to and item.get("created_at", "") > date_to:
            continue
        filtered.append(item)
        
    sorted_items = sorted(filtered, key=lambda x: x.get("created_at", ""), reverse=True)
    return sorted_items[:limit]


def safe_get_by_id(collection: str, item_id: str) -> dict[str, Any] | None:
    global _mongo_offline
    if not _mongo_offline:
        try:
            if ObjectId is not None:
                col = _collection(collection)
                if col is not None:
                    doc = col.find_one({"_id": ObjectId(item_id)})
                    return _serialize_doc(doc) if doc else None
        except Exception as exc:
            logger.warning("safe_get_by_id failed for MongoDB, falling back to in-memory: %s", exc)
            _mongo_offline = True

    # In-memory lookup fallback
    items = _in_memory_db.get(collection, [])
    for item in items:
        if item.get("id") == item_id:
            return item
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
