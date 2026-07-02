# =============================================================
# FILE: src/db/base.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: SQLAlchemy declarative Base for the policy/identity DB
#          (ADR_2026-06-29). Findings stay in S3 — this DB holds
#          org/project/user allow & deny lists + the Giggso baseline mirror.
#          A naming convention is set so Alembic emits stable, explicit
#          constraint/index names across migrations.
# =============================================================

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Stable names for indexes/constraints — keeps migrations deterministic.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base shared by every policy/identity model."""
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
