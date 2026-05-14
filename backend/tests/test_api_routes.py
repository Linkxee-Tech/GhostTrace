import os
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_analyze_url_invalid():
    response = client.post("/api/analyze-url", json={"url": "not-a-url"})
    assert response.status_code == 400


def test_analyze_log_ok():
    body = {"log_text": "failed login from 10.10.10.10 using powershell -enc AAAA"}
    response = client.post("/api/analyze-log", json=body)
    assert response.status_code == 200
    payload = response.json()
    assert "risk_score" in payload
    assert "threat_level" in payload
    assert "iocs" in payload


def test_monitor_add_and_status():
    add = client.post("/api/monitor/add", json={"url": "https://example.com"})
    assert add.status_code == 200
    status = client.get("/api/monitor/status")
    assert status.status_code == 200
    assert "watchlist" in status.json()


def test_history_endpoints():
    for path in ["/api/history/files", "/api/history/urls", "/api/history/logs", "/api/reports"]:
        response = client.get(path)
        assert response.status_code == 200
        assert "items" in response.json()


def test_generate_log_report():
    response = client.post("/api/generate-log-report", json={"log_text": "simple log sample"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"


def test_settings_api_keys_masked_roundtrip():
    os.environ["SETTINGS_ENCRYPTION_KEY"] = "mVjvHUrhKMYLyeWEQBAaduboyrhuA8sSKPuKY_Q-uA8="
    save = client.post(
        "/api/settings/api-keys",
        json={
            "ghosttrace_api_key": "ghst_1234567890",
            "virustotal_api_key": "vt_abcdef123456",
            "abuseipdb_api_key": "abuse_abcdef123456",
            "openai_api_key": "sk-proj-abcdef123456",
            "urlscan_api_key": "urlscan_abcdef123456",
            "phishtank_api_key": "pt_abcdef123456",
        },
    )
    assert save.status_code == 200
    out = client.get("/api/settings/api-keys")
    assert out.status_code == 200
    payload = out.json()
    assert payload["source"] in {"database", "none"}
    if payload["source"] == "database":
        assert payload["configured"]["ghosttrace_api_key"] is True
        assert payload["masked"]["ghosttrace_api_key"].endswith("7890")


def test_auth_missing_vs_invalid():
    os.environ["GHOSTTRACE_API_KEY"] = "test-secret"
    missing = client.post("/api/analyze-log", json={"log_text": "x"})
    assert missing.status_code == 401
    invalid = client.post("/api/analyze-log", json={"log_text": "x"}, headers={"x-api-key": "wrong"})
    assert invalid.status_code == 403
    ok = client.post("/api/analyze-log", json={"log_text": "x"}, headers={"x-api-key": "test-secret"})
    assert ok.status_code == 200
    os.environ["GHOSTTRACE_API_KEY"] = ""
