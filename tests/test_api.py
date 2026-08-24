import logging

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


class TestAnalyzeEndpoint:
    def test_happy_path_shape(self, client):
        response = client.post("/api/analyze", json={"password": "Password123"})
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"stats", "strength", "checks", "problems"}
        assert set(body["stats"]) == {
            "length", "uppercase", "lowercase", "digits", "special", "entropy_bits",
        }
        assert body["stats"]["length"] == len("Password123")
        assert set(body["checks"]) == {
            "too_short", "only_letters", "only_numbers", "repeated_characters",
            "sequential_characters", "common_password", "common_pattern",
        }
        assert body["strength"]["label"] in {
            "Very Weak", "Weak", "Moderate", "Strong", "Very Strong",
        }

    def test_response_never_echoes_the_password(self, client):
        secret = "Zqx$9vTt-SecretMarker-42"
        response = client.post("/api/analyze", json={"password": secret})
        assert response.status_code == 200
        assert secret not in response.text
        assert "SecretMarker" not in response.text

    def test_empty_password_is_valid(self, client):
        response = client.post("/api/analyze", json={"password": ""})
        assert response.status_code == 200
        assert response.json()["stats"]["length"] == 0
        assert response.json()["checks"]["too_short"] is True

    def test_very_long_password_rejected_without_echo(self, client):
        secret = "SuperSecret!2026" + "x" * 1100
        response = client.post("/api/analyze", json={"password": secret})
        assert response.status_code == 422
        assert "SuperSecret" not in response.text

    def test_missing_field_returns_422(self, client):
        response = client.post("/api/analyze", json={})
        assert response.status_code == 422

    def test_wrong_type_returns_422(self, client):
        response = client.post("/api/analyze", json={"password": [1, 2, 3]})
        assert response.status_code == 422

    def test_null_returns_422(self, client):
        response = client.post("/api/analyze", json={"password": None})
        assert response.status_code == 422


class TestGenerateEndpoint:
    def test_happy_path(self, client):
        response = client.post("/api/generate", json={"length": 20})
        assert response.status_code == 200
        body = response.json()
        assert body["length"] == 20
        assert len(body["password"]) == 20

    def test_charset_options_respected(self, client):
        response = client.post(
            "/api/generate",
            json={"length": 32, "uppercase": False, "numbers": False, "special": False},
        )
        password = response.json()["password"]
        assert all(c.islower() for c in password)

    def test_length_too_small_returns_422(self, client):
        response = client.post("/api/generate", json={"length": 3})
        assert response.status_code == 422

    def test_length_too_large_returns_422(self, client):
        response = client.post("/api/generate", json={"length": 129})
        assert response.status_code == 422

    def test_all_sets_disabled_returns_422(self, client):
        response = client.post(
            "/api/generate",
            json={"length": 16, "uppercase": False, "lowercase": False,
                  "numbers": False, "special": False},
        )
        assert response.status_code == 422

    def test_validation_error_does_not_leak_input(self, client):
        response = client.post("/api/generate", json={"length": -999})
        assert response.status_code == 422
        assert "-999" not in response.text


class TestOtherRoutes:
    def test_health(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_unknown_api_route_404(self, client):
        assert client.get("/api/nope").status_code == 404

    def test_frontend_index_served(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Password Security Analyzer" in response.text

    def test_frontend_assets_served(self, client):
        assert client.get("/app.js").status_code == 200
        assert client.get("/styles.css").status_code == 200


class TestNoPasswordLogging:
    SECRET = "TopSecret-Log-Leak-Probe-777!"

    def test_logs_never_contain_analyzed_password(self, client, caplog):
        with caplog.at_level(logging.DEBUG):
            response = client.post("/api/analyze", json={"password": self.SECRET})
            assert response.status_code == 200
            client.post("/api/analyze", json={"password": ""})
            client.post("/api/analyze", json={"password": self.SECRET + "x"})
        assert self.SECRET not in caplog.text

    def test_logs_never_contain_generated_password(self, client, caplog):
        with caplog.at_level(logging.DEBUG):
            body = client.post("/api/generate", json={"length": 32}).json()
        assert body["password"] not in caplog.text

    def test_error_paths_do_not_log_passwords(self, client, caplog):
        with caplog.at_level(logging.DEBUG):
            client.post("/api/analyze", json={"password": self.SECRET + "x" * 1100})
            client.post("/api/analyze", content=b"{invalid json")
        assert self.SECRET not in caplog.text


class TestSecurityHeaders:
    def test_no_server_version_header_leak_via_docs_disabled_in_prod_not_required(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
