"""CLI argument handling and exit codes. PLAN.md section 10.

`run_scan` is monkeypatched throughout — these tests exercise CLI logic
(filtering, exit-code contract, rendering dispatch), never the real host.
"""

from __future__ import annotations

import json

import pytest

from extension_searcher import cli
from extension_searcher.discovery import ScanResult
from extension_searcher.models import BrowserHit, Engine, ExtensionRecord, InstallOrigin, ScanError


def _fake_extension(**overrides) -> ExtensionRecord:
    base = dict(
        extension_id="abcdefghijklmnopabcdefghijklmnop",
        name="Fake Extension",
        version="1.0",
        description=None,
        browser="Google Chrome",
        browser_channel="Stable",
        engine=Engine.CHROMIUM,
        profile_dir="Default",
        profile_name=None,
        install_path="/fake",
        enabled=True,
        disabled_reason=None,
        state_source="secure_preferences",
        install_origin=InstallOrigin.WEBSTORE,
        update_url=None,
        signed_state=None,
        is_builtin=False,
        is_unpacked=False,
        manifest_version=3,
    )
    base.update(overrides)
    return ExtensionRecord(**base)


def test_filter_specs_by_engine():
    args = cli.build_parser().parse_args(["--engine", "gecko"])
    specs = cli._filter_specs(args)
    assert specs
    assert all(s.engine.value == "gecko" for s in specs)


def test_filter_specs_by_browser_name():
    args = cli.build_parser().parse_args(["--browser", "Google Chrome"])
    specs = cli._filter_specs(args)
    assert [s.name for s in specs] == ["Google Chrome"]


def test_extra_engine_flags_default_true():
    args = cli.build_parser().parse_args([])
    webkit, trident = cli._extra_engine_flags(args)
    assert webkit is True
    assert trident is True


def test_extra_engine_flags_respects_engine_filter():
    args = cli.build_parser().parse_args(["--engine", "chromium"])
    webkit, trident = cli._extra_engine_flags(args)
    assert webkit is False
    assert trident is False


def test_extra_engine_flags_respects_browser_filter():
    args = cli.build_parser().parse_args(["--browser", "Safari"])
    webkit, trident = cli._extra_engine_flags(args)
    assert webkit is True
    assert trident is False


def test_main_exit_0_on_clean_scan(monkeypatch, capsys):
    result = ScanResult(
        browsers=(BrowserHit("Google Chrome", Engine.CHROMIUM, True, ("/fake",), ()),),
        extensions=(_fake_extension(),),
        errors=(),
        unverified_paths=(),
    )
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: result)
    exit_code = cli.main(["--format", "json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["extensions"] == 1


def test_main_exit_2_when_no_browsers_found(monkeypatch, capsys):
    result = ScanResult(browsers=(), extensions=(), errors=(), unverified_paths=())
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: result)
    exit_code = cli.main(["--format", "json"])
    assert exit_code == 2


def test_main_exit_1_when_errors_present(monkeypatch, capsys):
    result = ScanResult(
        browsers=(BrowserHit("Google Chrome", Engine.CHROMIUM, True, ("/fake",), ()),),
        extensions=(),
        errors=(ScanError("/fake/bad.json", "json_decode", "boom"),),
        unverified_paths=(),
    )
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: result)
    exit_code = cli.main(["--format", "json"])
    assert exit_code == 1


def test_main_exit_3_when_filters_match_nothing():
    exit_code = cli.main(["--browser", "Nonexistent Browser", "--engine", "chromium"])
    assert exit_code == 3


def test_main_risk_flag_annotates_high_privilege(monkeypatch, capsys):
    risky = _fake_extension(host_permissions=("<all_urls>",))
    safe = _fake_extension(extension_id="p" * 32, host_permissions=("https://example.com/*",))
    result = ScanResult(
        browsers=(BrowserHit("Google Chrome", Engine.CHROMIUM, True, ("/fake",), ()),),
        extensions=(risky, safe),
        errors=(),
        unverified_paths=(),
    )
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: result)
    cli.main(["--format", "json", "--risk"])
    data = json.loads(capsys.readouterr().out)
    exts = {e["extension_id"]: e for e in data["extensions"]}
    assert "high_privilege_host_access" in exts["abcdefghijklmnopabcdefghijklmnop"]["warnings"]
    assert exts["p" * 32]["warnings"] == []


def test_main_writes_to_output_file(monkeypatch, tmp_path):
    result = ScanResult(
        browsers=(BrowserHit("Google Chrome", Engine.CHROMIUM, True, ("/fake",), ()),),
        extensions=(_fake_extension(),),
        errors=(),
        unverified_paths=(),
    )
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: result)
    out_path = tmp_path / "scan.json"
    exit_code = cli.main(["--format", "json", "--output", str(out_path)])
    assert exit_code == 0
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["summary"]["extensions"] == 1


def test_main_deprecated_flags_warn_but_do_not_fail(monkeypatch, capsys):
    result = ScanResult(
        browsers=(BrowserHit("Google Chrome", Engine.CHROMIUM, True, ("/fake",), ()),),
        extensions=(),
        errors=(),
        unverified_paths=(),
    )
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: result)
    exit_code = cli.main(
        ["--format", "json", "--deep", "--cache", "x.json", "--extra-root", "D:/Portable"]
    )
    assert exit_code == 0


@pytest.mark.parametrize("fmt", ["table", "json", "jsonl", "csv"])
def test_main_every_format_renders_without_error(monkeypatch, fmt):
    result = ScanResult(
        browsers=(BrowserHit("Google Chrome", Engine.CHROMIUM, True, ("/fake",), ()),),
        extensions=(_fake_extension(),),
        errors=(),
        unverified_paths=(),
    )
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: result)
    exit_code = cli.main(["--format", fmt])
    assert exit_code == 0
