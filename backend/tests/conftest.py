import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app import models
from app.config import settings
from app.security import hash_password
from app.database import get_session
from app.event_store import doc_id, get_event_store
from app.main import app


class FakeEventStore:
    """In-memory stand-in for OpenSearch so tests don't need Docker."""

    def __init__(self):
        self.docs = {}

    def index_events(self, events):
        for e in events:
            self.docs[doc_id(e)] = e
        return len(events)

    def search(self, filters, size):
        hits = [d for d in self.docs.values() if all(d.get(k) == v for k, v in filters.items())]
        return hits[:size]


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture
def store():
    return FakeEventStore()


@pytest.fixture
def client(engine, store):
    def override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_event_store] = lambda: store
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def make_user(engine):
    def _make(username="analyst1", role="analyst"):
        with Session(engine) as session:
            user = models.User(username=username, password_hash="x", role=role)
            session.add(user)
            session.commit()
            session.refresh(user)
            return user.id

    return _make


@pytest.fixture(autouse=True)
def auth_off(monkeypatch):
    """Most tests are about alerts, cases and events, not login: switch auth off.
    Tests of login and access use the `auth_on` fixture."""
    monkeypatch.setattr(settings, "auth_required", False)


@pytest.fixture
def auth_on(monkeypatch):
    monkeypatch.setattr(settings, "auth_required", True)
    monkeypatch.setattr(settings, "secret_key", "test-secret-key-for-pytest-only-0123456789")
    monkeypatch.setattr(settings, "api_key", "test-service-key")


@pytest.fixture
def make_login_user(engine):
    """Create a user with a real Argon2 password hash."""

    def _make(username="analyst1", role="analyst", password="correct-horse-battery", active=True):
        with Session(engine) as session:
            user = models.User(
                username=username, password_hash=hash_password(password), role=role, is_active=active
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            return user.id

    return _make


@pytest.fixture
def login(client):
    """Return Authorization headers for a user created with make_login_user."""

    def _login(username="analyst1", password="correct-horse-battery"):
        r = client.post("/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    return _login
