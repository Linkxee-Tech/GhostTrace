from fastapi import FastAPI
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import uuid
import os
from dotenv import load_dotenv
from app.api.routes import router
from app.api.websockets import ws_router

load_dotenv()


class TraceIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())
        request.state.trace_id = trace_id
        response = await call_next(request)
        response.headers["x-trace-id"] = trace_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app = FastAPI(
    title="GhostTrace API",
    description="AI-powered malware and suspicious file analyzer for digital forensics.",
    version="0.1.0",
)

cors_origins_env = os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174",
)
cors_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TraceIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(router, prefix="/api")
app.include_router(ws_router, prefix="/api")


@app.get("/health")
def health_check():
    return {"status": "ok", "application": "GhostTrace"}


@app.on_event("startup")
def enforce_production_security_config() -> None:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    if app_env in {"prod", "production"} and not os.getenv("GHOSTTRACE_API_KEY", "").strip():
        raise RuntimeError("GHOSTTRACE_API_KEY must be configured in production mode.")
