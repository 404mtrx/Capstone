"""OpenSearch login and TLS settings (the real server is checked by scripts/test_opensearch_auth.sh)."""
from opensearchpy.exceptions import AuthenticationException, AuthorizationException

from app import event_store
from app.config import settings


def build(monkeypatch, url, **overrides):
    seen = {}

    def fake_client(hosts, **kwargs):
        seen["hosts"], seen["kwargs"] = hosts, kwargs
        return object()

    monkeypatch.setattr(event_store, "OpenSearch", fake_client)
    for name, value in overrides.items():
        monkeypatch.setattr(settings, name, value)
    event_store.EventStore(url, "idx")
    return seen


def test_plain_http_without_a_login_sends_no_credentials(monkeypatch):
    seen = build(monkeypatch, "http://localhost:9200", opensearch_user="", opensearch_password="")
    assert seen["kwargs"] == {}


def test_https_with_a_login_uses_tls_and_basic_auth(monkeypatch):
    seen = build(monkeypatch, "https://localhost:9200", opensearch_user="sentinel_app",
                 opensearch_password="pw-123", opensearch_verify_certs=False, opensearch_ca_certs="")
    kw = seen["kwargs"]
    assert kw["http_auth"] == ("sentinel_app", "pw-123")
    assert kw["use_ssl"] is True and kw["verify_certs"] is False
    assert "ca_certs" not in kw


def test_certificate_checking_and_ca_file_can_be_turned_on(monkeypatch):
    seen = build(monkeypatch, "https://os.example:9200", opensearch_user="u", opensearch_password="p",
                 opensearch_verify_certs=True, opensearch_ca_certs="/etc/ca.pem")
    kw = seen["kwargs"]
    assert kw["verify_certs"] is True and kw["ssl_show_warn"] is True and kw["ca_certs"] == "/etc/ca.pem"


class RefusingStore:
    def __init__(self, exc):
        self.exc = exc

    def index_events(self, events):
        raise self.exc

    def search(self, filters, size):
        raise self.exc


EVENT = {"timestamp": "2026-10-08T14:30:00Z", "source": "linux", "event_type": "failed_login",
         "action": "failure", "severity": "medium", "message": "m", "source_ip": "10.0.0.9"}


def test_bad_opensearch_login_gives_503_and_leaks_no_secret(client, monkeypatch):
    from app.event_store import get_event_store
    from app.main import app

    monkeypatch.setattr(settings, "opensearch_password", "super-secret-os-pw")
    for exc in (AuthenticationException(401, "Unauthorized"), AuthorizationException(403, "forbidden")):
        app.dependency_overrides[get_event_store] = lambda e=exc: RefusingStore(e)
        post = client.post("/events", json=[EVENT])
        get = client.get("/events")
        assert post.status_code == 503 and get.status_code == 503
        assert "super-secret-os-pw" not in post.text + get.text
