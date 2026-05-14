import os
from typing import Any

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
except Exception:  # pragma: no cover
    MongoClient = None  # type: ignore
    PyMongoError = Exception  # type: ignore


_client: Any = None


def get_mongo_client() -> MongoClient:
    global _client
    if MongoClient is None:
        raise RuntimeError("pymongo is not installed.")
    if _client is not None:
        return _client

    uri = os.getenv("MONGODB_URI", "").strip()
    if not uri:
        raise RuntimeError("MONGODB_URI is not configured.")

    _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    return _client


def mongo_status() -> dict[str, Any]:
    try:
        client = get_mongo_client()
        client.admin.command("ping")
        return {"connected": True, "message": "MongoDB connection successful."}
    except (RuntimeError, PyMongoError) as exc:
        return {"connected": False, "message": f"MongoDB connection failed: {exc}"}
