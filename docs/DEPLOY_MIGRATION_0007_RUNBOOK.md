# Runbook — deploying past migration `0007` (Giggso-baseline removal)

## Why this exists

GSD ticket (2026-08-24): the Shadow AI Controls page's "Exceptions" summary
card disagreed with its own "Projects" tab (e.g. "1 active exception" vs
"0 exceptions across N projects"). Traced live (via direct DB query on
`patronai_policy`) to two things:

1. Two Patron-native demo projects ("Sample-GSD" / "Sample GSD 2",
   `external_source IS NULL` — never came from RavenHub) had dangling
   `approved_tools`/`blacklisted_tools` override rows attached. Those rows
   got counted in whatever computes the top-level "active exceptions"
   number, but couldn't be attributed to any project the "Projects" tab
   recognizes as real — hence the mismatch. **Cleaned up manually this
   session** (the two phantom projects + their cascade-deleted override
   rows were deleted directly from `patronai_policy` after read-verifying
   them first).
2. The deeper, permanent cause: the "exceptions" / "guarded override" /
   "Giggso baseline" concept those screens represent was **already removed
   from this codebase** on 2026-07-31
   (`cad6b3b`, `ADR_2026-07-31-remove-giggso-baseline-scope-priority-waterfall`,
   merged via PR #21) — replaced with a simpler scope-first allow/deny
   waterfall that has no separate "exception" tier to miscount in the first
   place. The environment serving the screenshots in this ticket is running
   code from before that change, so the whole bug class it describes no
   longer exists on `main` — it just hasn't reached that environment yet.

Confirmed live: that environment's `patronai_policy` database is stamped at
Alembic revision `0006_raven_flagged_tools` — exactly one revision behind
`main`'s current head, `0007_remove_giggso_baseline` (there is nothing
after `0007` yet). The `giggso_baseline_deny` table and the
`overrides_giggso`/`overrides_deny` columns on `approved_tools` still exist
there; the now-orphaned guarded-override REST router
(`routers/ravenhub_governance_writes_overrides.py`) was deleted from the
codebase in the same change, so that environment is also running stale
application code, not just a stale schema.

## What redeploying actually does here

Per `src/db/engine.py`'s `run_migrations()`: **Alembic migrations auto-run
to `head` once per process, on first DB access**, guarded by a Postgres
advisory lock (`PATRONAI_AUTO_MIGRATE=1` by default). There is no separate
manual `alembic upgrade head` step in normal operation — the schema gap
exists only because the currently-running process was started before
`0007` was merged and has not been restarted since. A plain redeploy
(pull latest `main`, rebuild, restart the `scanner` service) is expected to
self-migrate the database automatically.

## Steps

1. **Confirm auto-migrate isn't disabled** on the target host:
   ```bash
   grep -i PATRONAI_AUTO_MIGRATE .env   # must be unset, or "1"/"true" — NOT "0"/"false"
   ```
2. **Pull latest `main` and rebuild:**
   ```bash
   cd <patronai checkout on the server>
   git fetch origin && git checkout main && git pull
   docker compose -f ghost-ai-scanner/docker-compose.yml build scanner
   ```
3. **Restart the app service** (this is what triggers the auto-migration —
   the `postgres` and other services do not need to restart):
   ```bash
   docker compose -f ghost-ai-scanner/docker-compose.yml up -d scanner
   ```
4. **Watch the scanner logs for the migration running:**
   ```bash
   docker logs -f patronai 2>&1 | grep -i alembic
   ```
   Expect to see it advance through `0007_remove_giggso_baseline` (a data
   migration too — it converts any existing `overrides_giggso=true` /
   `overrides_deny=true` row into a plain approve first, clearing the two
   flags plus `reason`/`valid_until` — no attempt to preserve the override's
   audit trail, per the migration's own docstring — before dropping the
   columns).

## Verification (read-only — same checks used to diagnose this session)

```sql
-- Should now read 0007_remove_giggso_baseline
SELECT version_num FROM alembic_version;

-- Should now fail — the table is gone
SELECT count(*) FROM giggso_baseline_deny;

-- Should no longer list overrides_giggso / overrides_deny
SELECT column_name FROM information_schema.columns
WHERE table_name = 'approved_tools' ORDER BY column_name;
```

If the first query still shows `0006_raven_flagged_tools` after restarting
`scanner`, the new code did not actually start (check the rebuild/restart
actually picked up the new image, and re-check step 1).

## After this lands

The old "Baseline Providers / Allowed org-wide / Exceptions / Awaiting
decision" summary cards and the "Grant project exception" modal shown in
this ticket's screenshots have no backend left to call
(`ravenhub_governance_writes_overrides.py` is gone) — whatever frontend
renders that Controls page will need a corresponding update to whatever the
post-ADR Provider Governance UI is, or it will start erroring/blanking on
those specific sections. Loop in whoever owns that frontend before treating
this deploy as complete.

## References

- `ADR_2026-07-31-remove-giggso-baseline-scope-priority-waterfall` — commit
  `cad6b3b`, PR #21
- `alembic/versions/0007_remove_giggso_baseline.py`
- `src/db/engine.py` — auto-migrate mechanics
- Companion PRs for the rest of this ticket: Giggso-Inc/raven-enterprise#195,
  Giggso-Inc/PatronAI#31
