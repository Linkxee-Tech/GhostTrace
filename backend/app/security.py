import os
import time
import logging
from collections import defaultdict, deque
from fastapi import Header, HTTPException


RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 120
_rate_state: dict[str, deque[float]] = defaultdict(deque)
logger = logging.getLogger(__name__)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    required = os.getenv("GHOSTTRACE_API_KEY", "").strip()
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    if not required:
        if app_env in {"prod", "production"}:
            logger.error("GHOSTTRACE_API_KEY is missing in production mode.")
            raise HTTPException(status_code=500, detail="Server misconfiguration: API key is required in production.")
        return
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key.")
    if x_api_key != required:
        raise HTTPException(status_code=403, detail="Invalid API key.")


def enforce_rate_limit(client_id: str) -> None:
    now = time.time()
    q = _rate_state[client_id]
    while q and now - q[0] > RATE_LIMIT_WINDOW_SECONDS:
        q.popleft()
    if len(q) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    q.append(now)
