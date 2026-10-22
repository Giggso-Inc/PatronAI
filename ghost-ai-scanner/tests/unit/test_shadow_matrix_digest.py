"""Sheet rows for continued shadow use and stale decisions."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from jobs.shadow_matrix_digest import due_alerts


def _flag(tool, hours_ago, users, org="acme"):
    return SimpleNamespace(
        provider_pattern=tool,
        added_at=datetime.now(timezone.utc) - timedelta(hours=hours_ago),
        device_count=users,
        org_slug=org,
    )


def test_fresh_single_user_sends_nothing():
    assert due_alerts([_flag("chatgpt", 2, 1)]) == []


def test_continued_use_when_a_second_user_appears():
    rows = due_alerts([_flag("chatgpt", 5, 3)])
    assert [r["kind"] for r in rows] == ["continued"]
    assert rows[0]["additional_count"] == 2
    assert rows[0]["user_count"] == 3
    assert rows[0]["tool"] == "chatgpt"


def test_pending_72h_only_before_seven_days():
    rows = due_alerts([_flag("claude", 96, 1)])
    assert [r["kind"] for r in rows] == ["pending72"]


def test_pending_7d_does_not_also_send_72h():
    rows = due_alerts([_flag("claude", 24 * 8, 1)])
    assert [r["kind"] for r in rows] == ["pending7d"]
