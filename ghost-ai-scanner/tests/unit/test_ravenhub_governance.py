# =============================================================
# FILE: tests/unit/test_ravenhub_governance.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: Lock the RavenHub governance API layer (routers/
#          ravenhub_governance_reads.py, _writes_lists.py,
#          _writes_overrides.py) — request validation, actor
#          resolution (403 when the verified email isn't a policy-DB
#          user), and PolicyAuthzError -> 403 mapping. Does NOT
#          re-test db/governance_crud.py's own authz internals —
#          test_governance_crud_db.py already owns that; this file
#          only locks the API layer built on top of it.
#          Pure; no real DB — get_session/get_identity are stubbed.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — actor-resolution 403, scope/query
#                       validation, PolicyAuthzError mapping for
#                       approve/block/move/remove/override/deny-override.
# =============================================================

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from fastapi import HTTPException

from routers._raven_actor import resolve_actor
from routers.ravenhub_governance_reads import get_governance_scope, list_raven_flags
from routers.ravenhub_governance_writes_lists import (
    ApproveRequest, RemoveRequest, ResolveRavenFlagRequest,
    approve_provider, remove_provider_entry, resolve_raven_flag_endpoint,
)
from routers.ravenhub_governance_writes_overrides import (
    DenyOverrideRequest, OverrideRequest, deny_override_provider, override_giggso_baseline,
)


class _FakeSession:
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def _stub_get_session(monkeypatch, module):
    """Patch `db.engine.get_session` as seen via `module`'s own
    `from db.engine import get_session` (each router imports it locally
    inside the function body, so we patch the source module)."""
    import db.engine as engine_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: _FakeSession())


class _FakeActor:
    def __init__(self, is_org_admin=False, org_id="org-1"):
        self.is_org_admin = is_org_admin
        self.org_id = org_id
        self.id = "actor-1"


def _stub_identity(monkeypatch, actor, org_id):
    """Patch db.policy_queries.get_identity to return a fixed actor."""
    import db.policy_queries as pq
    monkeypatch.setattr(pq, "get_identity", lambda session, email: (actor, org_id, []))


# ── _resolve_actor: fail-closed on unrecognized identity ────────────────

def test_resolve_actor_raises_403_for_unrecognized_email(monkeypatch):
    import db.policy_queries as pq
    monkeypatch.setattr(pq, "get_identity", lambda session, email: (None, None, []))
    with pytest.raises(HTTPException) as exc:
        resolve_actor(_FakeSession(), "nobody@giggso.com")
    assert exc.value.status_code == 403


def test_resolve_actor_returns_actor_and_org_for_known_email(monkeypatch):
    import db.policy_queries as pq
    actor = _FakeActor()
    monkeypatch.setattr(pq, "get_identity", lambda session, email: (actor, "org-1", []))
    got_actor, got_org = resolve_actor(_FakeSession(), "dev@giggso.com")
    assert got_actor is actor
    assert got_org == "org-1"


# ── GET /governance/scope: query validation ─────────────────────────────

def test_governance_scope_requires_project_id_for_project_scope():
    with pytest.raises(HTTPException) as exc:
        get_governance_scope(scope="project", project_id=None, user_id=None, email="x@giggso.com")
    assert exc.value.status_code == 422


def test_governance_scope_requires_user_id_for_user_scope():
    with pytest.raises(HTTPException) as exc:
        get_governance_scope(scope="user", project_id=None, user_id=None, email="x@giggso.com")
    assert exc.value.status_code == 422


# ── Writes: actor-not-found fails closed before any governance_crud call ─

def test_approve_fails_closed_for_unresolvable_actor(monkeypatch):
    import db.policy_queries as pq
    monkeypatch.setattr(pq, "get_identity", lambda session, email: (None, None, []))
    _stub_get_session(monkeypatch, None)
    body = ApproveRequest(scope="org", provider_pattern="example.com")
    with pytest.raises(HTTPException) as exc:
        approve_provider(body, email="ghost@giggso.com")
    assert exc.value.status_code == 403


def test_remove_fails_closed_for_unresolvable_actor(monkeypatch):
    import db.policy_queries as pq
    monkeypatch.setattr(pq, "get_identity", lambda session, email: (None, None, []))
    _stub_get_session(monkeypatch, None)
    body = RemoveRequest(model="approved", row_id="row-1")
    with pytest.raises(HTTPException) as exc:
        remove_provider_entry(body, email="ghost@giggso.com")
    assert exc.value.status_code == 403


def test_remove_rejects_unknown_model_value(monkeypatch):
    actor = _FakeActor()
    _stub_identity(monkeypatch, actor, "org-1")
    _stub_get_session(monkeypatch, None)
    body = RemoveRequest(model="not-a-real-model", row_id="row-1")
    with pytest.raises(HTTPException) as exc:
        remove_provider_entry(body, email="dev@giggso.com")
    assert exc.value.status_code == 422


# ── PolicyAuthzError -> 403 mapping (override/deny-override) ────────────

def test_override_maps_policy_authz_error_to_403(monkeypatch):
    actor = _FakeActor(is_org_admin=False)
    _stub_identity(monkeypatch, actor, "org-1")
    _stub_get_session(monkeypatch, None)

    import db.governance_crud as crud
    def _deny(*a, **kw):
        raise crud.PolicyAuthzError("C8: org/project policy edits require an org admin")
    monkeypatch.setattr(crud, "add_approved", _deny)

    body = OverrideRequest(scope="org", provider_pattern="*.openai.com", reason="testing")
    with pytest.raises(HTTPException) as exc:
        override_giggso_baseline(body, email="dev@giggso.com")
    assert exc.value.status_code == 403
    assert "org admin" in exc.value.detail


def test_deny_override_maps_policy_authz_error_to_403(monkeypatch):
    actor = _FakeActor(is_org_admin=True)
    _stub_identity(monkeypatch, actor, "org-1")
    _stub_get_session(monkeypatch, None)

    import db.governance_crud as crud
    def _deny(*a, **kw):
        raise crud.PolicyAuthzError("D3: no reason")
    monkeypatch.setattr(crud, "grant_deny_override", _deny)

    body = DenyOverrideRequest(scope="project", provider_pattern="wider.ai", reason="  ", project_id="proj-1")
    with pytest.raises(HTTPException) as exc:
        deny_override_provider(body, email="admin@giggso.com")
    assert exc.value.status_code == 403
    assert "D3" in exc.value.detail


# ── GET /governance/raven-flags: project-membership scoping (review finding C1) ──

class _FakeFlag:
    def __init__(self, project_id, provider_pattern="example-mcp"):
        self.id = f"flag-{project_id}-{provider_pattern}"
        self.project_id = project_id
        self.provider_pattern = provider_pattern
        self.requested_by = "dev@giggso.com"
        self.note = None
        self.added_at = None


class _FakeProject:
    def __init__(self, id, display_name):
        self.id = id
        self.display_name = display_name


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows
    def filter(self, *a, **kw):
        return self
    def all(self):
        return self._rows


class _FakeSessionWithQuery(_FakeSession):
    """Adds .query(Model).filter(...).all() on top of _FakeSession, for the
    Project display_name lookup in list_raven_flags — set _rows on the class
    before use (see _stub_raven_flags_deps)."""
    _rows = []
    def query(self, model):
        return _FakeQuery(self._rows)


def _stub_raven_flags_deps(monkeypatch, *, flags, projects, member_project_ids=None, check_target_raises=False):
    import db.engine as engine_mod
    import db.governance_crud as crud
    import db.policy_queries as pq

    monkeypatch.setattr(crud, "list_pending_raven_flags", lambda session, *, org_id, project_id=None: (
        flags if project_id is None else [f for f in flags if f.project_id == project_id]
    ))

    def _check_target_in_org(session, *, org_id, project_id=None, user_id=None):
        if check_target_raises:
            raise crud.PolicyAuthzError("project_id not found in this org")
    monkeypatch.setattr(crud, "check_target_in_org", _check_target_in_org)

    monkeypatch.setattr(pq, "project_ids_for_user", lambda session, user_id: list(member_project_ids or []))

    session_cls = type("_FakeSessionForTest", (_FakeSessionWithQuery,), {"_rows": projects})
    monkeypatch.setattr(engine_mod, "get_session", lambda: session_cls())


def test_list_raven_flags_rejects_project_id_from_another_org(monkeypatch):
    """Review finding C1: a client-supplied project_id must be verified to
    belong to the caller's own org before being used — same check_target_in_org
    call the sibling GET /governance/scope already applies (PR#9, C1/C2)."""
    actor = _FakeActor(is_org_admin=False)
    _stub_identity(monkeypatch, actor, "org-1")
    _stub_raven_flags_deps(monkeypatch, flags=[], projects=[], check_target_raises=True)
    with pytest.raises(HTTPException) as exc:
        list_raven_flags(project_id="other-orgs-project", email="dev@giggso.com")
    assert exc.value.status_code == 403


def test_list_raven_flags_org_wide_restricts_non_admin_to_own_projects(monkeypatch):
    """Review finding C1: without a project_id, a non-admin must only see
    flags for projects they're a member of — being any org member is not by
    itself authorization to browse every other project's pending requests."""
    actor = _FakeActor(is_org_admin=False)
    _stub_identity(monkeypatch, actor, "org-1")
    flags = [_FakeFlag("proj-mine"), _FakeFlag("proj-not-mine")]
    projects = [_FakeProject("proj-mine", "Mine"), _FakeProject("proj-not-mine", "Not Mine")]
    _stub_raven_flags_deps(monkeypatch, flags=flags, projects=projects, member_project_ids=["proj-mine"])
    result = list_raven_flags(project_id=None, email="dev@giggso.com")
    assert [f.project_id for f in result.flags] == ["proj-mine"]


def test_list_raven_flags_org_wide_admin_sees_every_project(monkeypatch):
    """Admins keep the unrestricted org-wide view — that's the point of this
    mode for them (resolving without clicking into each project one at a
    time), unlike the non-admin case above."""
    actor = _FakeActor(is_org_admin=True)
    _stub_identity(monkeypatch, actor, "org-1")
    flags = [_FakeFlag("proj-a"), _FakeFlag("proj-b")]
    projects = [_FakeProject("proj-a", "A"), _FakeProject("proj-b", "B")]
    _stub_raven_flags_deps(monkeypatch, flags=flags, projects=projects, member_project_ids=[])
    result = list_raven_flags(project_id=None, email="admin@giggso.com")
    assert {f.project_id for f in result.flags} == {"proj-a", "proj-b"}
    assert result.is_admin is True


# ── POST /governance/raven-flags/{flag_id}/resolve: org-admin gate ──────

def test_resolve_raven_flag_requires_org_admin(monkeypatch):
    actor = _FakeActor(is_org_admin=False)
    _stub_identity(monkeypatch, actor, "org-1")
    _stub_get_session(monkeypatch, None)

    import db.governance_crud as crud
    def _fail(*a, **kw):
        raise AssertionError("resolve_raven_flag must not be called for a non-admin")
    monkeypatch.setattr(crud, "resolve_raven_flag", _fail)

    body = ResolveRavenFlagRequest(project_id="proj-1", approve=True)
    with pytest.raises(HTTPException) as exc:
        resolve_raven_flag_endpoint("flag-1", body, email="dev@giggso.com")
    assert exc.value.status_code == 403


def test_resolve_raven_flag_returns_404_for_unmatched_flag(monkeypatch):
    actor = _FakeActor(is_org_admin=True)
    _stub_identity(monkeypatch, actor, "org-1")
    _stub_get_session(monkeypatch, None)

    import db.governance_crud as crud
    monkeypatch.setattr(crud, "resolve_raven_flag", lambda *a, **kw: None)

    body = ResolveRavenFlagRequest(project_id="proj-1", approve=True)
    with pytest.raises(HTTPException) as exc:
        resolve_raven_flag_endpoint("flag-1", body, email="admin@giggso.com")
    assert exc.value.status_code == 404
