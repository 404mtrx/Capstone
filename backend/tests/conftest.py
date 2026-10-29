import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app import models
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
