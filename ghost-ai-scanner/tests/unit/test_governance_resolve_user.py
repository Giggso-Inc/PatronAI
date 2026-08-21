# Unit tests for check_target_in_org / resolve_user_in_org — no live DB.
# Locks the UUID-vs-str org compare and email-as-user_id resolution that
# caused Controls → User exception grants to 403 with
# "user_id not found in this org" for valid in-org people.

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from db import governance_crud as crud


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class _FakeSession:
    def __init__(self, *, by_id=None, by_email=None):
        self.by_id = by_id or {}
        self.by_email = by_email or {}

    def get(self, model, row_id):
        return self.by_id.get(str(row_id))

    def execute(self, _stmt):
        # resolve_user_in_org only uses execute for the email fallback.
        # Return whichever email was last looked up via a tiny hook: we
        # store a single candidate; tests that need email set by_email.
        if len(self.by_email) == 1:
            return _FakeResult(next(iter(self.by_email.values())))
        return _FakeResult(None)


def test_resolve_user_accepts_str_org_id_when_row_has_uuid():
    org = uuid.uuid4()
    uid = uuid.uuid4()
    user = SimpleNamespace(id=uid, org_id=org, email="jaswanth@giggso.com")
    session = _FakeSession(by_id={str(uid): user})

    # org_id as str — previously `UUID == str` was False → false 403.
    got = crud.resolve_user_in_org(session, str(org), str(uid))
    assert got is user


def test_resolve_user_accepts_email_for_in_org_member():
    org = uuid.uuid4()
    uid = uuid.uuid4()
    user = SimpleNamespace(id=uid, org_id=org, email="j.jaswanth@giggso.com")
    session = _FakeSession(by_email={"j.jaswanth@giggso.com": user})

    got = crud.resolve_user_in_org(session, org, "j.jaswanth@giggso.com")
    assert got.id == uid


def test_resolve_user_rejects_cross_org_uuid():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    uid = uuid.uuid4()
    user = SimpleNamespace(id=uid, org_id=org_b, email="other@x.com")
    session = _FakeSession(by_id={str(uid): user})

    with pytest.raises(crud.PolicyAuthzError, match="user_id not found in this org"):
        crud.resolve_user_in_org(session, org_a, str(uid))


def test_check_target_in_org_email_path():
    org = uuid.uuid4()
    uid = uuid.uuid4()
    user = SimpleNamespace(id=uid, org_id=org, email="member@z.com")
    session = _FakeSession(by_email={"member@z.com": user})

    crud.check_target_in_org(session, org_id=org, user_id="member@z.com")
