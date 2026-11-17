"""Unit tests for scripts/check_agent_version_bump.py."""
import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "check_agent_version_bump",
    Path(__file__).resolve().parents[3] / "scripts" / "check_agent_version_bump.py",
)
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)


def test_installer_change_without_bump_fails():
    assert _MOD.needs_bump(["ghost-ai-scanner/agent/install/hook_chain.ps1"])


def test_installer_change_with_bump_passes():
    assert not _MOD.needs_bump([
        "ghost-ai-scanner/agent/install/hook_chain.ps1",
        "ghost-ai-scanner/agent/AGENT_VERSION",
    ])


def test_unrelated_change_passes():
    assert not _MOD.needs_bump(["ghost-ai-scanner/src/retina/hub_client.py"])


def test_windows_separators_handled():
    assert _MOD.needs_bump([r"ghost-ai-scanner\agent\install\heartbeat.ps1"])
