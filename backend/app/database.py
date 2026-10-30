"""Database setup (SQLAlchemy 2.0 + SQLite).

All queries in this project go through the SQLAlchemy ORM, which sends user
data to the database as bound PARAMETERS, never by building SQL strings.
That is what protects us from SQL injection.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str) -> Engine:
    kwargs = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url or database_url in ("sqlite://", "sqlite:///"):
            kwargs["poolclass"] = StaticPool  # one shared connection for in-memory test DBs
    engine = create_engine(database_url, **kwargs)

    if database_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_tables(engine: Engine) -> None:
    from . import models  # noqa: F401  (registers the tables)
    Base.metadata.create_all(engine)
