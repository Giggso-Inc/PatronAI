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
from routers.ravenhub_governance_reads import get_governance_scope
from routers.ravenhub_governance_writes_lists import (
    ApproveRequest, RemoveRequest, approve_provider, remove_provider_entry,
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
