from pathlib import Path

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def _read(name: str) -> str:
    return (FRONTEND / name).read_text(encoding="utf-8")


class TestNoPersistentBrowserStorage:
    def test_no_local_storage_usage(self):
        assert "localStorage" not in _read("app.js")

    def test_no_session_storage_usage(self):
        assert "sessionStorage" not in _read("app.js")

    def test_no_cookie_access(self):
        assert "document.cookie" not in _read("app.js")
        assert "Set-Cookie" not in _read("app.js")

    def test_no_indexed_db_usage(self):
        assert "indexedDB" not in _read("app.js")

    def test_no_external_resources_loaded(self):
        html = _read("index.html")
        assert "http://" not in html
        assert "https://" not in html

    def test_no_external_requests_in_frontend_code(self):
        js = _read("app.js")
        assert "https://" not in js
        assert "http://" not in js
