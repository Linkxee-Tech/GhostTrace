import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.file_scanner import compute_entropy, compute_hashes

client = TestClient(app)


def test_compute_entropy_zero():
    assert compute_entropy(b"") == 0.0


def test_compute_entropy_text():
    assert compute_entropy(b"AAAA") == 0.0


def test_compute_hashes():
    hashes = compute_hashes(b"test")
    assert hashes["md5"] == "098f6bcd4621d373cade4e832627b4f6"


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_file_endpoint():
    sample = b"powershell -enc aGVsbG8= https://malicious.example/path 192.168.1.25"
    response = client.post(
        "/api/analyze-file",
        files={"file": ("sample.ps1", sample, "application/octet-stream")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "sample.ps1"
    assert payload["type"] == "file"
    assert isinstance(payload["iocs"], list)
    assert payload["severity"] in {"low", "medium", "high", "critical"}
    assert isinstance(payload["timeline"], list)
    assert isinstance(payload["recommendations"], list)
