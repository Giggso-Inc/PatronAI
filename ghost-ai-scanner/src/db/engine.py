# =============================================================
# FILE: src/db/engine.py
# VERSION: 1.1.0
# UPDATED: 2026-07-02
# OWNER: Giggso Inc
# PURPOSE: Lazy SQLAlchemy engine + session factory for the policy DB.
#          Reads DATABASE_URL from the environment ONLY — no credential
#          ever lives in code (security_log 2026-06-29). Import-safe when
#          the DB is not configured: nothing connects until get_engine()
#          is first called, so Phase A (CSV-backed) keeps working with no
#          DATABASE_URL set.
# POOL: pool_size=3 / max_overflow=2 / pre_ping / recycle 30 min
#       (ADR_2026-06-23 — Streamlit is single-threaded per session).
# MIGRATIONS: get_engine() applies Alembic to `head` once per process
#       (auto-migrate on startup — any entry point that touches the DB gets a
#       current schema). Toggle off with PATRONAI_AUTO_MIGRATE=0.
# AUDIT LOG:
#   v1.0.0  2026-06-29  Lazy engine + session factory.
#   v1.1.0  2026-07-02  Auto-run Alembic `upgrade head` on first engine build.
#   v1.2.0  2026-07-03  Guard auto-migrate with a Postgres advisory lock so
#                       concurrent workers/replicas don't race on DDL (PR#8 rvw).
# =============================================================

import logging
import os
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

_log = logging.getLogger(__name__)
_MIGRATED = False
# Fixed 64-bit key for the migration advisory lock (any constant, shared by all
# processes migrating THIS database). Prevents concurrent `alembic upgrade`.
_MIGRATION_LOCK_KEY = 728_411_053_921


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


def _auto_migrate_enabled() -> bool:
    """Auto-migrate is ON unless explicitly disabled (0/false/no)."""
    return (os.environ.get("PATRONAI_AUTO_MIGRATE", "1").strip().lower()
            not in ("0", "false", "no"))


def run_migrations() -> None:
    """Apply Alembic migrations up to `head`. Idempotent and once-per-process.

    Called automatically on first engine build so a fresh deploy comes up with
    a current schema instead of crashing on a missing table. Paths are resolved
    ABSOLUTELY (the app's CWD is not always ghost-ai-scanner/); the URL comes
    from DATABASE_URL via alembic/env.py — no credential in code. Best-effort:
    a failure is logged, not fatal (a later query surfaces the real error),
    matching the engine's import-safe philosophy."""
    global _MIGRATED
    if _MIGRATED or not _auto_migrate_enabled():
        return
    try:
        from alembic import command
        from alembic.config import Config
        from sqlalchemy import text
        from sqlalchemy.pool import NullPool
        # src/db/engine.py -> ghost-ai-scanner/
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        cfg = Config(os.path.join(root, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(root, "alembic"))
        # Serialise concurrent starters (multiple workers/replicas boot together):
        # hold a session-level Postgres advisory lock across the upgrade so only
        # one process runs DDL at a time; the rest block, then see a no-op.
        lock_engine = create_engine(database_url(), poolclass=NullPool, future=True)
        try:
            with lock_engine.connect() as conn:
                conn.exec_driver_sql(f"SELECT pg_advisory_lock({_MIGRATION_LOCK_KEY})")
                try:
                    command.upgrade(cfg, "head")
                    _log.info("policy DB migrated to head")
                finally:
                    conn.exec_driver_sql(f"SELECT pg_advisory_unlock({_MIGRATION_LOCK_KEY})")
        finally:
            lock_engine.dispose()
    except Exception as exc:                       # noqa: BLE001 — best effort
        _log.warning("auto-migration skipped/failed: %s", exc)
    finally:
        _MIGRATED = True   # don't retry every session; run once per process


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Build (once) and return the process-wide SQLAlchemy engine.
    Applies pending Alembic migrations before first use (auto-migrate)."""
    engine = create_engine(
        database_url(),
        pool_size=3,
        max_overflow=2,
        pool_pre_ping=True,   # validate connection before use
        pool_recycle=1800,    # recycle every 30 min — survives PG restarts
        future=True,
    )
    run_migrations()          # schema current before any caller queries
    return engine


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker:
    return sessionmaker(
        bind=get_engine(), class_=Session, expire_on_commit=False, future=True
    )


def get_session() -> Session:
    """Return a new Session. Caller owns its lifecycle (use as a context manager)."""
    return _session_factory()()


def reset_engine() -> None:
    """Dispose the cached engine/sessionmaker — for tests or after a config change.
    Also re-arms auto-migration so a new DATABASE_URL gets its schema applied."""
    global _MIGRATED
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    _session_factory.cache_clear()
    _MIGRATED = False
