import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import app  # noqa: E402


def test_home_serves_frontend():
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert response.headers["cache-control"] == "no-store"


def test_payloads_endpoint_returns_categories():
    response = TestClient(app).get("/api/payloads")
    assert response.status_code == 200
    assert response.json()["categories"]
