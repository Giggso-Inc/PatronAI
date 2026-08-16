#!/usr/bin/env python3
# =============================================================
# FILE: scripts/cleanup_orphaned_ravenhub_projects.py
# VERSION: 1.0.0
# UPDATED: 2026-08-16
# OWNER: Giggso Inc
# PURPOSE: One-off cleanup for patron `projects` rows left behind by
#          RavenHub Project deletes that happened BEFORE the D-101
#          delete-sync fix existed (routers/raven_enterprise_projects.py's
#          DELETE /projects/{external_ref} + db.governance_crud's
#          delete_project_by_external_ref). Every project synced from
#          RavenHub (external_source="ravenhub") whose external_ref
#          (RavenHub's group_id) is no longer in RavenHub's own live group
#          list is an orphan — the raven-side project it mirrors doesn't
#          exist anymore, and nothing will ever clean it up on its own.
#
#          Confirmed live on 2026-08-16: 20 of 25 patron project rows for
#          org "giggso" had no matching raven group left (several literally
#          named delete-proj/del/dele/proj-del — leftovers from testing the
#          delete flow itself).
#
#          Patron and Raven are separate systems/databases with no live
#          cross-check, so this script does NOT guess which rows are
#          orphaned (name heuristics like "contains delete", or
#          member_count == 0, are both unreliable — a genuinely-synced
#          project can have member_count 0 or 1, and an orphan can too, as
#          the confirmed data showed). Instead it takes the CURRENT list of
#          live RavenHub group_ids as explicit input and diffs against it —
#          get that list from RavenHub itself:
#            GET /api/raven/engineering-projects/cards-detail?org=<org_uuid>
#          via the RavenHub UI/DevTools (same way the D-101 investigation
#          confirmed this gap), save the response JSON to a file, and pass
#          it with --live-groups.
#
#          SAFE BY DEFAULT: dry-run unless --apply is passed. Always prints
#          the full candidate list before doing anything. Requires
#          DATABASE_URL (same as the other one-off DB scripts in this repo).
#
# USAGE:
#   # 1. Dry run — see what WOULD be deleted, changes nothing:
#   python scripts/cleanup_orphaned_ravenhub_projects.py \
#       --org-slug giggso --live-groups live_groups.json
#
#   # 2. Actually delete, once the candidate list looks right:
#   python scripts/cleanup_orphaned_ravenhub_projects.py \
#       --org-slug giggso --live-groups live_groups.json --apply
#
#   --live-groups accepts either shape:
#     - the raw cards-detail response: {"groups": [{"group_id": "...", ...}, ...]}
#     - a plain JSON array of group_id strings: ["id1", "id2", ...]
# AUDIT LOG:
#   v1.0.0  2026-08-16  Initial — D-101 cleanup for pre-existing orphans.
# =============================================================

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from db.models_identity import Org, Project, ProjectMember


def _load_live_group_ids(path: str) -> set[str]:
    """Accepts either the raw cards-detail JSON ({"groups": [...]}) or a
    plain JSON array of group_id strings. Never raises on a shape mismatch —
    returns an empty set and lets the caller decide what to do (an empty
    live-set would mark EVERYTHING as an orphan, so callers should treat an
    empty result here as "something's wrong with the input file", not
    "nothing is live")."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR: could not read/parse --live-groups file '{path}': {exc}", file=sys.stderr)
        return set()

    if isinstance(data, list):
        return {str(g) for g in data if g}
    if isinstance(data, dict) and isinstance(data.get("groups"), list):
        return {str(g.get("group_id")) for g in data["groups"] if g.get("group_id")}

    print(f"ERROR: unrecognized --live-groups shape in '{path}' — expected a JSON array "
          "or a {\"groups\": [...]} object.", file=sys.stderr)
    return set()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org-slug", required=True, help="patron Org.slug to clean up, e.g. giggso")
    parser.add_argument("--live-groups", required=True,
                        help="path to a JSON file listing RavenHub's currently-live group_ids "
                             "(cards-detail response, or a plain JSON array)")
    parser.add_argument("--apply", action="store_true",
                        help="actually delete the orphans. Without this flag: dry run only.")
    args = parser.parse_args()

    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        print("ERROR: DATABASE_URL is not set.", file=sys.stderr)
        return 1

    live_group_ids = _load_live_group_ids(args.live_groups)
    if not live_group_ids:
        print("ERROR: no live group_ids loaded — refusing to run (an empty live-set would "
              "flag every synced project as an orphan). Check --live-groups content.", file=sys.stderr)
        return 1

    engine = create_engine(db_url, future=True)
    with Session(engine) as session:
        org = session.execute(select(Org).where(Org.slug == args.org_slug)).scalar_one_or_none()
        if org is None:
            print(f"ERROR: no org with slug '{args.org_slug}' found.", file=sys.stderr)
            return 1

        # Same (Project, member_count) join pattern as governance_crud.list_projects,
        # so the printed count is real, not a guessed/nonexistent Project attribute.
        synced = session.execute(
            select(Project, func.count(ProjectMember.user_id))
            .outerjoin(ProjectMember, ProjectMember.project_id == Project.id)
            .where(
                Project.org_id == org.id,
                Project.external_source == "ravenhub",
                Project.external_ref.is_not(None),
            )
            .group_by(Project.id)
        ).all()

        orphans = [(p, count) for (p, count) in synced if p.external_ref not in live_group_ids]

        print(f"Org '{args.org_slug}': {len(synced)} RavenHub-synced project(s), "
              f"{len(orphans)} orphan(s) (external_ref not in the {len(live_group_ids)} live group_ids given).")
        if not orphans:
            print("Nothing to clean up.")
            return 0

        print()
        print(f"{'id':<38} {'slug':<28} {'display_name':<28} {'external_ref':<38} member_count")
        for p, member_count in orphans:
            print(f"{str(p.id):<38} {p.slug:<28} {p.display_name:<28} {str(p.external_ref):<38} {member_count}")
        print()

        if not args.apply:
            print(f"DRY RUN — no changes made. Re-run with --apply to delete these {len(orphans)} row(s) "
                  "(and their cascaded members/flags).")
            return 0

        for p, _count in orphans:
            session.delete(p)
        session.commit()
        print(f"Deleted {len(orphans)} orphaned project row(s).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
