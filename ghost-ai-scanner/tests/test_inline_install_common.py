"""ghost-ai-scanner/scripts/inline_install_common.py -- idempotency,
anchor-placement, and --check-mode tests.

This is PatronAI's copy of raven-enterprise's tools/inline_install_common.py
(independent repos, no shared package mechanism yet). Added in response to
review on PatronAI #90 (M2): this copy had no test coverage at all, unlike
the raven-enterprise original.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inline_install_common as iic  # noqa: E402

MODULE_SRC = """#Requires -Version 5.1
# module header, stripped on extraction
function Get-Widget {
    return 1
}
Export-ModuleMember -Function Get-Widget
"""

TARGET_SRC = """#Requires -Version 5.1
# some header
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "installer body"
"""


def test_extract_functions_strips_requires_and_export_module_member():
    body = iic.extract_functions(MODULE_SRC)
    assert "#Requires" not in body
    assert "Export-ModuleMember" not in body
    assert "function Get-Widget" in body


def test_inline_inserts_right_after_first_error_action_preference_line():
    functions = iic.extract_functions(MODULE_SRC)
    result = iic.inline(TARGET_SRC, functions)
    lines = result.splitlines()
    eap_idx = next(i for i, l in enumerate(lines) if l.strip().startswith("$ErrorActionPreference"))
    # The inlined block's start marker must appear before any of the
    # target's own post-$ErrorActionPreference logic (the
    # SecurityProtocol line here), and after $ErrorActionPreference itself.
    start_idx = next(i for i, l in enumerate(lines) if l.startswith(iic.START_MARKER))
    sp_idx = next(i for i, l in enumerate(lines) if "SecurityProtocol" in l)
    assert eap_idx < start_idx < sp_idx
    assert "function Get-Widget" in result


def test_inline_is_idempotent_and_does_not_duplicate():
    functions = iic.extract_functions(MODULE_SRC)
    once = iic.inline(TARGET_SRC, functions)
    twice = iic.inline(once, functions)
    assert twice.count(iic.START_MARKER) == 1
    assert twice.count("function Get-Widget") == 1


def test_inline_re_run_picks_up_a_changed_module_source():
    functions_v1 = iic.extract_functions(MODULE_SRC)
    once = iic.inline(TARGET_SRC, functions_v1)

    module_v2 = MODULE_SRC.replace("return 1", "return 2")
    functions_v2 = iic.extract_functions(module_v2)
    twice = iic.inline(once, functions_v2)

    assert "return 2" in twice
    assert "return 1" not in twice
    assert twice.count(iic.START_MARKER) == 1


def test_inline_refuses_without_an_anchor_line():
    functions = iic.extract_functions(MODULE_SRC)
    with pytest.raises(SystemExit):
        iic.inline("# no anchor here at all\nWrite-Host 'hi'\n", functions)


def test_inline_handles_backslashes_in_module_source():
    # Regression test: pattern.sub(block, text) treats `block` as a regex
    # REPLACEMENT TEMPLATE, not a literal string -- a module comment
    # containing a Windows path backslash sequence (e.g. "C:\Windows\..."
    # or, as found live, "...\W...") raised "bad escape \W" and crashed
    # the tool outright on any re-run. Caught in PR #702's second review
    # round; fixed with pattern.sub(lambda _m: block, text).
    module_with_backslash = MODULE_SRC.replace(
        "# module header, stripped on extraction",
        "# module header -- note the path C:\\Windows\\Sysnative and the \\W token",
    )
    functions = iic.extract_functions(module_with_backslash)
    once = iic.inline(TARGET_SRC, functions)
    # Re-run (the path that crashed): must not raise, and must still carry
    # the backslash content through verbatim.
    twice = iic.inline(once, functions)
    assert "C:\\Windows\\Sysnative" in twice
    assert twice.count(iic.START_MARKER) == 1


def test_check_mode_reports_match_and_mismatch(tmp_path):
    import subprocess

    module_path = tmp_path / "Module.psm1"
    target_path = tmp_path / "target.ps1"
    module_path.write_text(MODULE_SRC, encoding="utf-8")
    target_path.write_text(TARGET_SRC, encoding="utf-8")

    script = Path(__file__).resolve().parents[1] / "scripts" / "inline_install_common.py"

    # Target hasn't been inlined at all yet -> drift (exit 1).
    result = subprocess.run(
        [sys.executable, str(script), "--module", str(module_path), "--target", str(target_path), "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "DRIFT" in result.stdout

    # Actually inline it, then --check must report a clean match (exit 0).
    out_path = tmp_path / "target.ps1.built"
    subprocess.run(
        [sys.executable, str(script), "--module", str(module_path), "--target", str(target_path), "--out", str(out_path)],
        check=True,
    )
    target_path.write_text(out_path.read_text(encoding="utf-8"), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(script), "--module", str(module_path), "--target", str(target_path), "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout
