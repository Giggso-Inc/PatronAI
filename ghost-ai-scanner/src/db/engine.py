# =============================================================
# FILE: src/db/engine.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Lazy SQLAlchemy engine + session factory for the policy DB.
#          Reads DATABASE_URL from the environment ONLY — no credential
#          ever lives in code (security_log 2026-06-29). Import-safe when
#          the DB is not configured: nothing connects until get_engine()
#          is first called, so Phase A (CSV-backed) keeps working with no
#          DATABASE_URL set.
# POOL: pool_size=3 / max_overflow=2 / pre_ping / recycle 30 min
#       (ADR_2026-06-23 — Streamlit is single-threaded per session).
# =============================================================

import os
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def database_url() -> str:
    """Return DATABASE_URL or raise a clear, actionable error.

    Never returns a default with embedded credentials — an unset URL is a
    configuration error, not something to paper over silently."""
    url = (os.environ.get("DATABASE_URL") or "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set — the policy DB is unavailable. "
            "Set it (e.g. postgresql+psycopg2://patronai:***@postgres:5432/"
            "patronai_policy) or run the CSV-backed policy path instead."
        )
    return url


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Build (once) and return the process-wide SQLAlchemy engine."""
    return create_engine(
        database_url(),
        pool_size=3,
        max_overflow=2,
        pool_pre_ping=True,   # validate connection before use
        pool_recycle=1800,    # recycle every 30 min — survives PG restarts
        future=True,
    )


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker:
    return sessionmaker(
        bind=get_engine(), class_=Session, expire_on_commit=False, future=True
    )


def get_session() -> Session:
    """Return a new Session. Caller owns its lifecycle (use as a context manager)."""
    return _session_factory()()


def reset_engine() -> None:
    """Dispose the cached engine/sessionmaker — for tests or after a config change."""
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    _session_factory.cache_clear()
