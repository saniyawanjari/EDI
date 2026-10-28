"""Database connection (Phase 5). SQLAlchemy 2.0 style. PostgreSQL or SQLite."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import settings

SQLITE_FALLBACK_URL = "sqlite:///./audit.db"


class Base(DeclarativeBase):
    """All tables inherit from this."""


def _make_engine(url: str):
    kwargs = {}
    if url.startswith("sqlite"):
        # FastAPI uses several threads; SQLite must allow that.
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, pool_pre_ping=True, **kwargs)


def _build_engine():
    engine = _make_engine(settings.database_url)
    if not settings.database_url.startswith("sqlite"):
        try:
            with engine.connect():
                pass  # just test that the server answers
        except Exception as e:  # noqa: BLE001
            # SQLite FALLBACK (as required): keep working with a local file.
            print(f"WARNING: database not reachable ({e.__class__.__name__}). "
                  f"Falling back to {SQLITE_FALLBACK_URL}")
            engine = _make_engine(SQLITE_FALLBACK_URL)
    return engine


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    """Create all tables if they do not exist (called at startup)."""
    import models  # noqa: F401  (importing registers the tables on Base)

    Base.metadata.create_all(engine)
