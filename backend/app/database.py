from sqlmodel import Session, create_engine

from app.config import settings

engine = create_engine(settings.database_url, echo=False)


def get_session():
    """FastAPI dependency: yields a DB session per request."""
    with Session(engine) as session:
        yield session
