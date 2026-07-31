# =============================================================
# FILE: src/db/seeding.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: One-time-per-org population of the policy DB. PURE DB writes —
#          callers pass already-parsed data (users.json dict, CSV rows), so
#          this is testable against a live DB without S3. Every step is
#          idempotent by data (dedup), so this is a re-sync (DB = source of
#          truth), safe to call on every startup.
#          db/ depends on scoring/ only (one-way).
#          ADR_2026-07-31 (OQ-1): every org gets its OWN starter deny list
#          seeded at bootstrap from `_starter_deny_rows()` below — a local,
#          repo-bundled file, never an S3 read. This replaces the old
#          global `giggso_baseline_deny` table; there is no shared table,
#          every org's copy is independent from the moment it's seeded.
# DEPENDS: sqlalchemy, db.models_*
# AUDIT LOG:
#   v1.0.0  2026-06-30  Initial S3->DB seed incl. Giggso baseline table.
#   v2.0.0  2026-07-31  ADR_2026-07-31: drop seed_giggso_baseline() call;
#                       starter deny content now feeds seed_org_lists()
#                       directly via a local bundled CSV, per org.
# =============================================================

import csv
import logging
import os

from sqlalchemy import select

from db.models_identity import Org, User
from db.models_policy import ApprovedTool, BlacklistedTool, SchemaMigration
from scoring.policy import _norm

log = logging.getLogger("marauder-scan.db.seeding")

SEED_MARKER = "s3_policy_seed_v1"

# Bundled locally (ghost-ai-scanner/config/unauthorized.csv) — NOT fetched
# from S3 for seeding purposes. That same file may still be pushed to S3 by
# main.py's seed_config_files() for the UNRELATED ingestion-layer matcher
# (src/matcher/loader.py) — this read is independent of that and never
# touches the network.
_STARTER_DENY_CSV = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "unauthorized.csv",
)


def _starter_deny_rows() -> list:
    """Starter org-deny content (OQ-1), read once from the repo-bundled CSV.
    Returns [] if the file is missing/unreadable — seeding must never crash
    on this, an org just starts with an empty deny list in that case."""
    try:
        with open(_STARTER_DENY_CSV, encoding="utf-8") as f:
            body = "\n".join(ln for ln in f if not ln.lstrip().startswith("#"))
        return list(csv.DictReader(body.splitlines()))
    except OSError:
        return []


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
                         is_org_admin=is_admin))
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


def _pattern_meta(rows, pattern_col: str) -> dict:
    """Map pattern -> {category, severity} from CSV rows that carry those
    columns (deny_rows/deny_code_rows/starter_deny_rows). First-seen wins on
    a pattern collision across sources. Used so a seeded BlacklistedTool
    keeps its real category (e.g. "AI Coding Assistants") instead of
    reading back as an uncategorised "unknown" provider in the Overview
    tab — the category info existed in the CSV all along, it just wasn't
    being persisted."""
    out: dict = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        pat = _norm(row.get(pattern_col))
        if not pat or pat in out:
            continue
        cat = (row.get("category") or "").strip() or None
        sev = (row.get("severity") or "").strip().upper() or None
        if sev not in (None, "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            sev = None
        if cat or sev:
            out[pat] = {"category": cat, "severity": sev}
    return out


def seed_org_lists(session, org_id, *, allow_rows=(), allow_code_rows=(),
                   deny_rows=(), deny_code_rows=(), starter_deny_rows=()) -> tuple:
    """Seed org-scope approved_tools + blacklisted_tools from CSV rows.
    Deduped against existing org-scope patterns. Returns (n_allow, n_deny).

    `starter_deny_rows` (OQ-1): every org's OWN starter deny content — folded
    into the deny set like any other org-deny source. Not a separate table,
    not shared across orgs; each org's copy is independent from here on.

    OQ-4 (ADR_2026-07-31): a pattern can never hold both an approve and a
    deny row at the same scope (enforced by a DB trigger — migration 0007).
    Seeding must not crash the WHOLE batch over one conflicting starter/CSV
    row: an org's own EXISTING explicit decision always wins over anything
    this seed would otherwise add, so a candidate that collides with an
    opposite-polarity row already in the DB is silently skipped (logged),
    never inserted, never treated as an error."""
    have_allow = {
        p for (p,) in session.execute(
            select(ApprovedTool.domain_pattern).where(
                ApprovedTool.org_id == org_id, ApprovedTool.scope == "org"))
    }
    existing_deny_rows = list(session.execute(
        select(BlacklistedTool).where(
            BlacklistedTool.org_id == org_id, BlacklistedTool.scope == "org")
    ).scalars())
    have_deny = {r.domain for r in existing_deny_rows}
    # Seed only the real match-pattern columns (the provider glob), NOT the
    # human-readable `name` column — name is a label, not a pattern.
    allow_candidates = (_patterns(allow_rows, "domain_pattern")
                        | _patterns(allow_code_rows, "pattern"))
    deny_candidates = (_patterns(deny_rows, "domain")
                       | _patterns(deny_code_rows, "pattern")
                       | _patterns(starter_deny_rows, "domain"))
    # category/severity metadata, so Overview shows the CSV's real category
    # (e.g. "AI Coding Assistants") instead of an uncategorised "unknown".
    # Priority: org-custom rows first, starter content last (a customer's
    # own labelling for a pattern should win if it ever overlaps).
    deny_meta = {
        **_pattern_meta(starter_deny_rows, "domain"),
        **_pattern_meta(deny_code_rows, "pattern"),
        **_pattern_meta(deny_rows, "domain"),
    }

    # Allow is the higher-priority signal (an explicit customer allow_rows/
    # allow_code_rows entry always beats a generic starter deny) — resolve
    # it first, then exclude anything already/about-to-be approved from the
    # deny side, so a within-THIS-BATCH collision (e.g. allow_rows and
    # starter_deny_rows both naming the same pattern) can't hit the trigger
    # either, not just a collision against rows already in the DB.
    final_allow = allow_candidates - have_deny - have_allow
    final_deny = deny_candidates - have_allow - final_allow - have_deny

    skipped_allow = allow_candidates & have_deny
    skipped_deny = (deny_candidates & have_allow) | (deny_candidates & final_allow)
    if skipped_allow:
        log.warning("seed_org_lists: skipping %d allow candidate(s) already "
                    "denied at org scope: %s", len(skipped_allow),
                    sorted(skipped_allow)[:10])
    if skipped_deny:
        log.warning("seed_org_lists: skipping %d deny candidate(s) already/"
                    "about-to-be approved at org scope: %s", len(skipped_deny),
                    sorted(skipped_deny)[:10])

    # Self-heal: a row seeded before category/severity persistence existed
    # (or before this pattern had metadata available) picks it up on the
    # next re-sync — consistent with "safe to run on every startup".
    n_backfilled = 0
    for r in existing_deny_rows:
        if r.category is not None or r.domain not in deny_meta:
            continue
        meta = deny_meta[r.domain]
        r.category = meta.get("category")
        if r.severity is None:
            r.severity = meta.get("severity")
        n_backfilled += 1
    if n_backfilled:
        log.info("seed_org_lists: backfilled category/severity on %d existing row(s)",
                 n_backfilled)

    n_allow = n_deny = 0
    for pat in final_allow:
        session.add(ApprovedTool(org_id=org_id, scope="org",
                                 name=pat, domain_pattern=pat,
                                 reason="seeded from CSV"))
        n_allow += 1
    for pat in final_deny:
        meta = deny_meta.get(pat, {})
        session.add(BlacklistedTool(org_id=org_id, scope="org",
                                    name=pat, domain=pat,
                                    category=meta.get("category"),
                                    severity=meta.get("severity"),
                                    reason="seeded from CSV"))
        n_deny += 1
    session.flush()
    return n_allow, n_deny


def seed_all(session, *, org_slug, org_name, bucket, users_map=None,
             scanned_emails=(), allow_rows=(), allow_code_rows=(),
             deny_rows=(), deny_code_rows=()) -> dict:
    """Reconcile the whole policy DB from parsed S3 data + the local starter
    deny content (OQ-1). Safe to run on EVERY startup — every step is
    idempotent by data (dedup), so this is a re-sync (DB = source of truth),
    not a one-shot. Returns NEW-row counts. The SEED_MARKER is recorded for
    audit only; it no longer gates the run."""
    org = ensure_org(session, slug=org_slug, display_name=org_name, s3_bucket=bucket)
    n_users = upsert_users(session, org.id, users_map, scanned_emails)
    n_allow, n_deny = seed_org_lists(
        session, org.id, allow_rows=allow_rows, allow_code_rows=allow_code_rows,
        deny_rows=deny_rows, deny_code_rows=deny_code_rows,
        starter_deny_rows=_starter_deny_rows())

    if session.get(SchemaMigration, SEED_MARKER) is None:
        session.add(SchemaMigration(version=SEED_MARKER))
    session.commit()
    return {"seeded": True, "org_id": str(org.id), "users": n_users,
            "approved": n_allow, "blacklisted": n_deny}
