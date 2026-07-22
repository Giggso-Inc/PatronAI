# =============================================================
# FILE: tests/unit/test_raven_identity.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: Lock routers/_raven_identity.py's verify_ravenhub_identity —
#          the caller-identity JWT check shared by every RavenHub
#          router (PR#9 review, C1). Extracted from test_ravenhub.py
#          v1.3.0 when the function itself moved out of ravenhub.py
#          in v1.5.0 so the new governance routers could reuse it.
#          Pure; no real S3/DB — everything is stubbed.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Missing/invalid/expired token, wrong signing
#                       secret, missing email claim, secret not
#                       configured, valid-token happy path.
# =============================================================

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from fastapi import HTTPException
from jose import jwt as jose_jwt

import routers._raven_identity as raven_identity
from routers._raven_identity import verify_ravenhub_identity

_TEST_SECRET = "test-only-secret-never-used-in-prod"


def _make_token(secret=_TEST_SECRET, algorithm="HS256", **claims):
    return jose_jwt.encode(claims, secret, algorithm=algorithm)


def test_verify_identity_missing_secret_configured_returns_503(monkeypatch):
    """If RAVEN_JWT_SECRET isn't set, fail closed (503), not silently
    accept unverifiable tokens."""
    monkeypatch.setattr(raven_identity, "_RAVEN_JWT_SECRET", "")
    token = _make_token(email="dev@giggso.com")

    with pytest.raises(HTTPException) as exc:
        verify_ravenhub_identity(x_raven_identity=token)
    assert exc.value.status_code == 503


def test_verify_identity_missing_header_returns_401(monkeypatch):
    monkeypatch.setattr(raven_identity, "_RAVEN_JWT_SECRET", _TEST_SECRET)

    with pytest.raises(HTTPException) as exc:
        verify_ravenhub_identity(x_raven_identity=None)
    assert exc.value.status_code == 401
    assert "Missing" in exc.value.detail


def test_verify_identity_malformed_token_returns_401(monkeypatch):
    monkeypatch.setattr(raven_identity, "_RAVEN_JWT_SECRET", _TEST_SECRET)

    with pytest.raises(HTTPException) as exc:
        verify_ravenhub_identity(x_raven_identity="not-a-real-jwt")
    assert exc.value.status_code == 401


def test_verify_identity_wrong_signing_secret_returns_401(monkeypatch):
    """A token signed with a DIFFERENT secret than RAVEN_JWT_SECRET must
    be rejected — this is the actual signature check, not just decoding."""
    monkeypatch.setattr(raven_identity, "_RAVEN_JWT_SECRET", _TEST_SECRET)
    token = _make_token(secret="a-different-secret-entirely", email="dev@giggso.com")

    with pytest.raises(HTTPException) as exc:
        verify_ravenhub_identity(x_raven_identity=token)
    assert exc.value.status_code == 401
    assert "Invalid or expired" in exc.value.detail


def test_verify_identity_expired_token_returns_401(monkeypatch):
    monkeypatch.setattr(raven_identity, "_RAVEN_JWT_SECRET", _TEST_SECRET)
    expired = _make_token(email="dev@giggso.com", exp=0)  # epoch 0 — long expired

    with pytest.raises(HTTPException) as exc:
        verify_ravenhub_identity(x_raven_identity=expired)
    assert exc.value.status_code == 401
    assert "Invalid or expired" in exc.value.detail


def test_verify_identity_missing_email_claim_returns_401(monkeypatch):
    monkeypatch.setattr(raven_identity, "_RAVEN_JWT_SECRET", _TEST_SECRET)
    token = _make_token(sub="user-123", role="member")  # no `email` claim

    with pytest.raises(HTTPException) as exc:
        verify_ravenhub_identity(x_raven_identity=token)
    assert exc.value.status_code == 401
    assert "email claim" in exc.value.detail


def test_verify_identity_valid_token_returns_normalized_email(monkeypatch):
    monkeypatch.setattr(raven_identity, "_RAVEN_JWT_SECRET", _TEST_SECRET)
    token = _make_token(sub="user-123", email="  Dev@Giggso.COM  ", role="member")

    result = verify_ravenhub_identity(x_raven_identity=token)
    assert result == "dev@giggso.com"
