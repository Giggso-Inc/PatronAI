"""Unit tests for Patron Hub licence gate."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from notify import hub_licence_gate as gate  # noqa: E402


@pytest.fixture(autouse=True)
def _reset():
    gate.clear()
    yield
    gate.clear()


def test_should_skip_after_403():
    class Err(Exception):
        code = 403

        def read(self, n=800):
            return b'{"code":"LICENCE_EXPIRED"}'

    assert gate.note_error(Err()) is True
    assert gate.should_skip() is True


def test_clear_unblocks():
    gate.mark_expired(ttl_sec=60)
    assert gate.is_blocked() is True
    gate.clear()
    assert gate.is_blocked() is False
