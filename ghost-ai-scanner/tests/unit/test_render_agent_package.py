# =============================================================
# FILE: tests/unit/test_render_agent_package.py
# VERSION: 1.0.0
# UPDATED: 2026-04-19
# OWNER: Giggso Inc
# PURPOSE: Unit tests for render_agent_package orchestration.
#          All S3/SES calls are mocked — no AWS credentials needed.
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial — agent delivery system
#   v1.1.0  2026-09-01  Cover enable_packetbeat -> {{ENABLE_PACKETBEAT}}
#                       context threading (default off, explicit on).
#   v1.2.0  2026-09-01  Cover the Windows installer's self-elevation
#                       block (UAC relaunch) - real template content,
#                       not mocked, via the real agent_renderer.
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


def test_enable_packetbeat_defaults_to_off():
    """Callers that don't pass enable_packetbeat must keep today's real
    behaviour (Packetbeat never runs) rather than silently opting in."""
    store    = _make_store()
    renderer = _make_renderer()

    render_agent_package(
        recipient_name  = "Default Off",
        recipient_email = "off@example.com",
        os_type         = "mac",
        store           = store,
        renderer        = renderer,
        send_email      = False,
    )

    second_ctx = renderer.render.call_args_list[1][0][1]
    assert second_ctx["ENABLE_PACKETBEAT"] == "0"


def test_enable_packetbeat_true_flows_into_both_render_passes():
    """The per-recipient choice must reach both the placeholder pass
    (used to mint the token) and the final pass (real URLs)."""
    store    = _make_store()
    renderer = _make_renderer()

    render_agent_package(
        recipient_name    = "Packetbeat On",
        recipient_email   = "on@example.com",
        os_type           = "windows",
        store             = store,
        renderer          = renderer,
        send_email        = False,
        enable_packetbeat = True,
    )

    first_ctx  = renderer.render.call_args_list[0][0][1]
    second_ctx = renderer.render.call_args_list[1][0][1]
    assert first_ctx["ENABLE_PACKETBEAT"]  == "1"
    assert second_ctx["ENABLE_PACKETBEAT"] == "1"


def test_enable_packetbeat_resolves_against_the_real_templates():
    """A mocked renderer can't catch a typo'd {{PLACEHOLDER}} name - render
    through the REAL agent_renderer against the real template files so a
    missing/renamed context key surfaces as a real KeyError, not a
    silent pass."""
    from store import agent_renderer

    store = _make_store()

    result = render_agent_package(
        recipient_name    = "Real Render",
        recipient_email   = "real@example.com",
        os_type           = "windows",
        store             = store,
        renderer          = agent_renderer,
        send_email        = False,
        enable_packetbeat = True,
    )

    assert result["success"] is True
    ps1_calls = [c for c in store._put.call_args_list
                 if c.args and str(c.args[0]).endswith("setup_agent.ps1")]
    assert ps1_calls, "expected a setup_agent.ps1 upload"
    ps1_body = ps1_calls[0].args[1].decode("utf-8-sig")
    assert '$EnablePacketbeat  = "1"' in ps1_body
    assert "{{ENABLE_PACKETBEAT}}" not in ps1_body


def test_windows_installer_self_elevates_before_doing_any_work():
    """Every Windows recipient must be prompted for Administrator via UAC
    before the script does anything else - not just Packetbeat recipients.
    Checks real template content (not a mocked renderer) so a regression
    here (block removed, or moved after real setup work) is caught."""
    from store import agent_renderer

    store = _make_store()

    render_agent_package(
        recipient_name  = "Elevation Check",
        recipient_email = "elevate@example.com",
        os_type         = "windows",
        store           = store,
        renderer        = agent_renderer,
        send_email      = False,
    )

    ps1_calls = [c for c in store._put.call_args_list
                 if c.args and str(c.args[0]).endswith("setup_agent.ps1")]
    ps1_body = ps1_calls[0].args[1].decode("utf-8-sig")

    assert "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" in ps1_body
    assert "Start-Process powershell -Verb RunAs" in ps1_body

    # Must come before the first real setup action (Python/bcrypt check),
    # not be dead code stuck after work has already started.
    elevate_idx = ps1_body.index("Start-Process powershell -Verb RunAs")
    first_real_work_idx = ps1_body.index('python --version')
    assert elevate_idx < first_real_work_idx


def test_enable_scanners_resolves_against_the_real_templates_windows():
    """Same class of bug test_enable_packetbeat_resolves_against_the_real_templates
    guards against: a mocked renderer can't catch a typo'd {{PLACEHOLDER}}
    name for the three new ZIP payloads. Render through the real
    agent_renderer so a missing/renamed context key raises KeyError here,
    not silently ships a broken installer."""
    from store import agent_renderer

    store = _make_store()

    result = render_agent_package(
        recipient_name    = "Scanners Windows",
        recipient_email   = "scanners-win@example.com",
        os_type           = "windows",
        store             = store,
        renderer          = agent_renderer,
        send_email        = False,
        enable_scanners   = True,
    )

    assert result["success"] is True
    ps1_calls = [c for c in store._put.call_args_list
                 if c.args and str(c.args[0]).endswith("setup_agent.ps1")]
    ps1_body = ps1_calls[0].args[1].decode("utf-8-sig")

    assert '$EnableScanners    = "1"' in ps1_body
    assert "{{ENABLE_SCANNERS}}" not in ps1_body
    assert "{{SCANNERS_AI_SDK_ZIP_B64}}" not in ps1_body
    assert "{{SCANNERS_EXTENSION_ZIP_B64}}" not in ps1_body
    assert "{{SCANNERS_APIKEY_ZIP_B64}}" not in ps1_body
    # The actual zip payload landed — not just the flag.
    assert "Expand-ScannerPackage" in ps1_body
    assert '"ai_sdk_scanner"' in ps1_body


def test_enable_scanners_resolves_against_the_real_templates_unix():
    """Same check on the sh side — different placeholder-substitution
    path, different string quoting, needs its own real-render proof."""
    from store import agent_renderer

    store = _make_store()

    result = render_agent_package(
        recipient_name    = "Scanners Unix",
        recipient_email   = "scanners-unix@example.com",
        os_type           = "mac",
        store             = store,
        renderer          = agent_renderer,
        send_email        = False,
        enable_scanners   = True,
    )

    assert result["success"] is True
    sh_calls = [c for c in store._put.call_args_list
                if c.args and str(c.args[0]).endswith("setup_agent.sh")]
    sh_body = sh_calls[0].args[1].decode("utf-8")

    assert 'PATRONAI_ENABLE_SCANNERS="1"' in sh_body
    assert "{{ENABLE_SCANNERS}}" not in sh_body
    assert "{{SCANNERS_AI_SDK_ZIP_B64}}" not in sh_body
    assert "{{SCANNERS_EXTENSION_ZIP_B64}}" not in sh_body
    assert "{{SCANNERS_APIKEY_ZIP_B64}}" not in sh_body
    assert "_unpack_scanner_pkg" in sh_body


def test_enable_scanners_defaults_off():
    """No enable_scanners kwarg -> "0", matching every other optional
    companion's default-off contract."""
    from store import agent_renderer

    store = _make_store()

    render_agent_package(
        recipient_name  = "Scanners Default",
        recipient_email = "scanners-default@example.com",
        os_type         = "mac",
        store           = store,
        renderer        = agent_renderer,
        send_email      = False,
    )

    sh_calls = [c for c in store._put.call_args_list
                if c.args and str(c.args[0]).endswith("setup_agent.sh")]
    sh_body = sh_calls[0].args[1].decode("utf-8")
    assert 'PATRONAI_ENABLE_SCANNERS="0"' in sh_body
