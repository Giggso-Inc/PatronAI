# =============================================================
# FILE: src/db/seeding.py
# VERSION: 1.0.0
# UPDATED: 2026-06-30
# OWNER: Giggso Inc
# PURPOSE: One-time population of the policy DB from existing S3 data
#          (ADR_2026-06-29). PURE DB writes — callers pass already-parsed
#          data (users.json dict, CSV rows), so this is testable against a
#          live DB without S3. Guarded by a schema_migrations marker so it
#          runs once and is safe to call on every startup.
#          db/ depends on scoring/ only (one-way).
# DEPENDS: sqlalchemy, db.models_*, db.policy_queries
# =============================================================

from sqlalchemy import select

from db.models_identity import Org, User
from db.models_policy import ApprovedTool, BlacklistedTool, SchemaMigration
from db.policy_queries import seed_giggso_baseline
from scoring.policy import _norm

SEED_MARKER = "s3_policy_seed_v1"


def ensure_org(session, *, slug, display_name, s3_bucket) -> Org:
    """Get-or-create the org by slug."""
    org = session.execute(select(Org).where(Org.slug == slug)).scalar_one_or_none()
    if org is None:
        org = Org(slug=slug, display_name=display_name, s3_bucket=s3_bucket,
                  created_by="seed")
        session.add(org)
        session.flush()
    return org


def _display_name(email: str) -> str:
    """Human-ish name from an email local-part: k.sanjaykumar -> K Sanjaykumar."""
    local = (email or "").split("@", 1)[0]
    return " ".join(p for p in local.replace(".", " ").replace("_", " ").split()).title()


def upsert_users(session, org_id, users_map: dict = None, scanned_emails=()) -> int:
    """Reconcile the org's people from BOTH sources (P1):
      - users_map: users.json-shaped {email: {role, is_admin}} (auth/admins)
      - scanned_emails: event-owners seen in findings (members)
    Inserts new users (display_name derived from email) and backfills
    display_name on existing rows. Returns count of NEW users inserted."""
    want: dict = {}
    for email, rec in (users_map or {}).items():
        e = _norm(email)
        if e:
            want[e] = bool((rec or {}).get("is_admin"))
    for email in scanned_emails or []:
        e = _norm(email)
        if e and e not in want:
            want[e] = False   # scanned-only people are members, not admins

    existing = {
        u.email: u for u in session.execute(
            select(User).where(User.org_id == org_id)).scalars()
    }
    n = 0
    for e, is_admin in want.items():
        u = existing.get(e)
        if u is not None:
            if not u.display_name:           # backfill missing display_name
                u.display_name = _display_name(e)
            continue
        session.add(User(org_id=org_id, email=e, display_name=_display_name(e),
                         is_org_admin=is_admin,
                         role="ORG_ADMIN" if is_admin else "VIEWER"))
        n += 1
    session.flush()
    return n


def _patterns(rows, *cols) -> set:
    out = set()
    for row in rows or []:
        for c in cols:
            v = _norm(row.get(c) if isinstance(row, dict) else row)
            if v and not v.startswith("#"):
                out.add(v)
    return out


def seed_org_lists(session, org_id, *, allow_rows=(), allow_code_rows=(),
                   deny_rows=(), deny_code_rows=()) -> tuple:
    """Seed org-scope approved_tools + blacklisted_tools from CSV rows.
    Deduped against existing org-scope patterns. Returns (n_allow, n_deny)."""
    have_allow = {
        p for (p,) in session.execute(
            select(ApprovedTool.domain_pattern).where(
                ApprovedTool.org_id == org_id, ApprovedTool.scope == "org"))
    }
    have_deny = {
        d for (d,) in session.execute(
            select(BlacklistedTool.domain).where(
                BlacklistedTool.org_id == org_id, BlacklistedTool.scope == "org"))
    }
    # Seed only the real match-pattern columns (the provider glob), NOT the
    # human-readable `name` column — name is a label, not a pattern.
    n_allow = n_deny = 0
    for pat in (_patterns(allow_rows, "domain_pattern")
                | _patterns(allow_code_rows, "pattern")):
        if pat not in have_allow:
            session.add(ApprovedTool(org_id=org_id, scope="org",
                                     name=pat, domain_pattern=pat,
                                     reason="seeded from CSV"))
            n_allow += 1
    for pat in (_patterns(deny_rows, "domain")
                | _patterns(deny_code_rows, "pattern")):
        if pat not in have_deny:
            session.add(BlacklistedTool(org_id=org_id, scope="org",
                                        name=pat, domain=pat,
                                        reason="seeded from CSV"))
            n_deny += 1
    session.flush()
    return n_allow, n_deny


def seed_all(session, *, org_slug, org_name, bucket, users_map=None,
             scanned_emails=(), giggso_rows=(), allow_rows=(), allow_code_rows=(),
             deny_rows=(), deny_code_rows=()) -> dict:
    """Reconcile the whole policy DB from parsed S3 data. Safe to run on
    EVERY startup — every step is idempotent by data (dedup), so this is a
    re-sync (DB = source of truth), not a one-shot. Returns NEW-row counts.
    The SEED_MARKER is recorded for audit only; it no longer gates the run."""
    org = ensure_org(session, slug=org_slug, display_name=org_name, s3_bucket=bucket)
    n_users = upsert_users(session, org.id, users_map, scanned_emails)
    n_giggso = seed_giggso_baseline(session, giggso_rows)  # dedups + commits
    n_allow, n_deny = seed_org_lists(
        session, org.id, allow_rows=allow_rows, allow_code_rows=allow_code_rows,
        deny_rows=deny_rows, deny_code_rows=deny_code_rows)

    if session.get(SchemaMigration, SEED_MARKER) is None:
        session.add(SchemaMigration(version=SEED_MARKER))
    session.commit()
    return {"seeded": True, "org_id": str(org.id), "users": n_users,
            "giggso": n_giggso, "approved": n_allow, "blacklisted": n_deny}
