# =============================================================
# FILE: tests/unit/test_hook_chain_ps1_legacy.py
# VERSION: 1.0.0
# UPDATED: 2026-11-06
# OWNER: Giggso Inc
# PURPOSE: Regression guard for the Windows git-template bug. Older
#          setup_agent.ps1 copied raw pre_commit_hook.ps1 into
#          ~/.patronai/git-template/hooks/pre-commit. Git for Windows
#          runs hooks via sh.exe, so every repo cloned afterwards had
#          a hook that failed every commit (worse once Raven appended
#          its bash block under a bash shebang). Exercises the real
#          Install-PatronAIChainHook from agent/install/hook_chain.ps1.
# =============================================================

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_CHAIN_LIB = _ROOT / "agent" / "install" / "hook_chain.ps1"
_RAW_HOOK = _ROOT / "agent" / "install" / "pre_commit_hook.ps1"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("powershell") is None,
    reason="hook_chain.ps1 targets Windows PowerShell",
)

_RAVEN_BLOCK = (
    "# raven-asset-inventory-pre-commit\n"
    'REPO_ROOT="$(git rev-parse --show-toplevel)"\n'
    "echo raven-ran\n"
)


def _install(profile: Path, hooks_dir: Path) -> None:
    script = (
        f"$env:USERPROFILE = '{profile}'; "
        f". '{_CHAIN_LIB}'; "
        f"if (-not (Install-PatronAIChainHook -HooksDir '{hooks_dir}')) {{ exit 3 }}"
    )
    res = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=60,
    )
    assert res.returncode == 0, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"


@pytest.fixture()
def env(tmp_path):
    profile = tmp_path / "profile"
    (profile / ".patronai").mkdir(parents=True)
    shutil.copy(_RAW_HOOK, profile / ".patronai" / "pre_commit_hook.ps1")
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    return profile, hooks


def _assert_clean_chain(hook: Path) -> None:
    raw = hook.read_bytes()
    assert raw.startswith(b"#!/bin/sh\n"), raw[:40]       # no BOM, sh shebang
    assert b"\r" not in raw                                # LF only
    text = raw.decode("utf-8")
    assert "PatronAI managed pre-commit chain" in text
    assert "$ConfigPath" not in text                       # no inlined PowerShell
    assert "pre_commit_hook.ps1" in text


def test_raw_template_hook_replaced_by_chain(env):
    profile, hooks = env
    # Exactly what the old installer put in git-template/hooks/pre-commit.
    (hooks / "pre-commit").write_bytes(b"\xef\xbb\xbf" + _RAW_HOOK.read_bytes())
    _install(profile, hooks)
    _assert_clean_chain(hooks / "pre-commit")
    assert not (hooks / "pre-commit.pre-patronai").exists()


def test_raven_block_kept_and_powershell_stripped(env):
    profile, hooks = env
    raw = _RAW_HOOK.read_text(encoding="utf-8").replace("\r\n", "\n")
    (hooks / "pre-commit").write_text(
        "#!/usr/bin/env bash\n" + raw + "\n" + _RAVEN_BLOCK, encoding="utf-8", newline="\n"
    )
    _install(profile, hooks)
    _assert_clean_chain(hooks / "pre-commit")
    preserved = (hooks / "pre-commit.pre-patronai").read_text(encoding="utf-8")
    assert preserved.startswith("#!/usr/bin/env bash\n")
    assert "raven-asset-inventory-pre-commit" in preserved
    assert "PatronAI pre-commit hook" not in preserved
    assert "$ConfigPath" not in preserved


def test_chain_runs_under_git_sh(env, tmp_path):
    """The installed chain must parse under sh (what Git for Windows uses)."""
    profile, hooks = env
    _install(profile, hooks)
    sh = shutil.which("sh") or shutil.which("bash")
    if sh is None:
        pytest.skip("no sh available")
    res = subprocess.run([sh, "-n", str(hooks / "pre-commit")], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


def test_idempotent(env):
    profile, hooks = env
    (hooks / "pre-commit").write_text("#!/bin/sh\necho user-hook\n", newline="\n")
    _install(profile, hooks)
    first = (hooks / "pre-commit").read_bytes(), (hooks / "pre-commit.pre-patronai").read_bytes()
    _install(profile, hooks)
    second = (hooks / "pre-commit").read_bytes(), (hooks / "pre-commit.pre-patronai").read_bytes()
    assert first == second
    assert b"user-hook" in second[1]
