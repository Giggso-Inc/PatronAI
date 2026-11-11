# =============================================================
# FILE: tests/unit/test_render_agent_package.py
# VERSION: 1.0.0
# UPDATED: 2026-04-19
# OWNER: Giggso Inc
# PURPOSE: Unit tests for render_agent_package orchestration.
#          All S3/SES calls are mocked — no AWS credentials needed.
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial — agent delivery system
# =============================================================

import os
import sys
import json
import types
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

from render_agent_package import render_agent_package


# ── Fixtures ──────────────────────────────────────────────────

def _make_store(token: str = "test-token-123") -> MagicMock:
    """Return a fully mocked AgentStore."""
    store              = MagicMock()
    store.bucket       = "test-bucket"
    store.region       = "us-east-1"
    store.generate_otp.return_value = "123456"
    store.hash_otp.return_value     = "$2b$12$fakehash"
    store.create_package.return_value = token
    store.get_presigned_urls.return_value = {
        "installer_url":  "https://s3.example.com/installer",
        "meta_url":       "https://s3.example.com/meta",
        "status_put_url": "https://s3.example.com/status",
    }
    store._put = MagicMock(return_value=True)
    return store


def _make_renderer() -> MagicMock:
    """Return a renderer mock that returns a templated string."""
    renderer        = MagicMock()
    renderer.render = MagicMock(return_value="#!/bin/bash\n# rendered script\n")
    return renderer


# ── Tests ──────────────────────────────────────────────────────

def test_successful_package_generation_mac():
    """Happy path: mac package is generated and result contains OTP + URLs."""
    store    = _make_store()
    renderer = _make_renderer()

    result = render_agent_package(
        recipient_name  = "Jane Smith",
        recipient_email = "jane@example.com",
        os_type         = "mac",
        store           = store,
        renderer        = renderer,
        send_email      = False,
    )

    assert result["success"] is True
    assert result["otp"] == "123456"
    assert result["token"] == "test-token-123"
    assert "installer_url" in result
    assert "meta_url" in result


def test_successful_package_generation_windows():
    """Windows platform selects .ps1 template."""
    store    = _make_store()
    renderer = _make_renderer()

    result = render_agent_package(
        recipient_name  = "Bob Jones",
        recipient_email = "bob@example.com",
        os_type         = "windows",
        store           = store,
        renderer        = renderer,
        send_email      = False,
    )

    assert result["success"] is True
    # _put should be called for the re-rendered .ps1
    final_put_calls = [str(c) for c in store._put.call_args_list]
    assert any("ps1" in c for c in final_put_calls)


def test_unsupported_os_type_returns_error():
    """Unknown os_type must fail fast without touching S3."""
    store    = _make_store()
    renderer = _make_renderer()

    result = render_agent_package(
        recipient_name  = "Test",
        recipient_email = "test@example.com",
        os_type         = "freebsd",
        store           = store,
        renderer        = renderer,
        send_email      = False,
    )

    assert result["success"] is False
    assert "freebsd" in result["error"]
    store.create_package.assert_not_called()


def test_s3_upload_failure_returns_error():
    """When create_package returns None, result must indicate failure."""
    store              = _make_store()
    store.create_package.return_value = None
    renderer           = _make_renderer()

    result = render_agent_package(
        recipient_name  = "Test",
        recipient_email = "test@example.com",
        os_type         = "linux",
        store           = store,
        renderer        = renderer,
        send_email      = False,
    )

    assert result["success"] is False
    assert "S3" in result["error"] or "upload" in result["error"].lower()


def test_renderer_called_five_times_for_real_urls():
    """
    Template is rendered five times today:
      1. Pre-render .sh with placeholder context to mint the token.
      2. Render final .sh with real presigned URLs.
      3. Render final .ps1 with the same real URLs.
      4. Render uninstall_agent.sh with token baked in.
      5. Render uninstall_agent.ps1 with token baked in.
    History: assertion was == 2 (pre-ps1), then == 3 (pre-uninstall),
    now == 5 after uninstall scripts were added to render_agent_package.py.
    """
    store    = _make_store(token="abc-def-123")
    renderer = _make_renderer()

    render_agent_package(
        recipient_name  = "Alice",
        recipient_email = "alice@example.com",
        os_type         = "mac",
        store           = store,
        renderer        = renderer,
        send_email      = False,
    )

    assert renderer.render.call_count == 5
    # Call 2 (.sh with real URLs) must carry the real token and META_URL.
    second_ctx = renderer.render.call_args_list[1][0][1]
    assert second_ctx["TOKEN"] == "abc-def-123"
    assert second_ctx["META_URL"] == "https://s3.example.com/meta"


# ── Regression: nested here-string terminator (GSD install failure, 2026-11-11) ──
#
# Uses the REAL agent_renderer + REAL templates/scripts on disk (not the
# dummy-string renderer mock above) because the bug only exists in how the
# actual setup_agent.ps1.template text interacts with scan.ps1's own embedded
# here-string -- a mocked renderer can't exercise it.

from store import agent_renderer as _real_agent_renderer  # noqa: E402


def _make_real_store(token: str = "real-token-456") -> MagicMock:
    store = MagicMock()
    store.bucket = "test-bucket"
    store.region = "us-east-1"
    store.generate_otp.return_value = "123456"
    store.hash_otp.return_value = "$2b$12$fakehash"
    store.create_package.return_value = token
    store.get_presigned_urls.return_value = {
        "installer_url": "https://example.com/installer?X-Amz-Signature=deadbeef",
        "meta_url": "https://example.com/meta?X-Amz-Signature=deadbeef",
        "status_put_url": "https://example.com/status?X-Amz-Signature=deadbeef",
        "heartbeat_put_url": "https://example.com/heartbeat?X-Amz-Signature=deadbeef",
        "scan_put_url": "https://example.com/scan?X-Amz-Signature=deadbeef",
        "authorized_get_url": "https://example.com/auth?X-Amz-Signature=deadbeef",
        "urls_refresh_url": "https://example.com/refresh?X-Amz-Signature=deadbeef",
    }
    store.write_url_bundle.return_value = None
    put_calls = {}
    store._put = MagicMock(side_effect=lambda key, body, content_type: put_calls.__setitem__(key, body))
    store._put_calls = put_calls
    return store


def test_windows_render_does_not_leak_nested_herestring_terminator():
    """scan.ps1 writes its own INLINE_SCAN_PYTHON payload to disk via
    `@' ... '@ | Set-Content ...` so it can also run standalone (see
    apply_update.*'s update bundle). PowerShell's single-quoted here-string
    has no nesting concept: when scan.ps1's content is spliced into
    setup_agent.ps1.template's OUTER {{INLINE_SCAN_PS1}} here-string, that
    inner closing '@ line used to prematurely terminate the OUTER
    here-string, and everything rendered after it (including log_rotate.py)
    was then parsed as literal top-level PowerShell instead of string data.
    Confirmed live against a real install attempt (GSD, 2026-11-11): the
    downloaded installer failed with "Unexpected token '}'" and "'from'
    keyword is not supported" cascades despite being byte-for-byte what the
    server rendered.
    """
    store = _make_real_store()

    result = render_agent_package(
        recipient_name="Regression Test",
        recipient_email="regression@example.com",
        os_type="windows",
        store=store,
        renderer=_real_agent_renderer,
        send_email=False,
    )

    assert result["success"] is True

    ps1_key = next(k for k in store._put_calls if k.endswith("setup_agent.ps1"))
    rendered = store._put_calls[ps1_key].decode("utf-8-sig")

    # scan.ps1's own inner closing delimiter must survive ONLY as neutralized
    # (leading space) text -- never as a column-0 line, which would close the
    # outer here-string early.
    assert "\n'@ | Set-Content -Path $PyTmp" not in rendered
    assert "\n '@ | Set-Content -Path $PyTmp" in rendered

    # The log_rotate.py section -- the part that visibly broke -- must still
    # be present as literal, unexecuted here-string content, closed by the
    # OUTER template's own (untouched) column-0 terminator.
    assert "\n'@ | Set-Content -Path $LogRotateScript -Encoding UTF8" in rendered
    assert "from __future__ import annotations" in rendered
