import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app import models
from app.database import get_session
from app.main import app


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture
def client(engine):
    def override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_session
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
