"""End-to-end orchestration test. PLAN.md section 3 pipeline: registry ->
discovery -> parser -> report, exercised through `run_scan` itself rather
than any one parser in isolation — this is the piece the live-host smoke
testing covered manually but no unit test exercised directly."""

from __future__ import annotations

import json

from extension_searcher import discovery
from extension_searcher.models import Engine
from extension_searcher.registry import BrowserSpec, PathEntry, RootKind


def _build_chrome_profile(root, ext_id: str) -> None:
    profile_dir = root / "chrome_profile" / "Default"
    version_dir = profile_dir / "Extensions" / ext_id / "1.0_0"
    version_dir.mkdir(parents=True)
    manifest = {"name": "Discovered Extension", "version": "1.0", "manifest_version": 3}
    (version_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_run_scan_end_to_end_finds_extension(tmp_path, monkeypatch):
    ext_id = "abcdefghijklmnopabcdefghijklmnop"
    _build_chrome_profile(tmp_path, ext_id)

    fake_spec = BrowserSpec(
        "Fake Chrome",
        Engine.CHROMIUM,
        "Stable",
        windows=(PathEntry(RootKind.HOME, "chrome_profile"),),
        macos=(PathEntry(RootKind.HOME, "chrome_profile"),),
        linux=(PathEntry(RootKind.HOME, "chrome_profile"),),
    )

    monkeypatch.setattr(discovery, "resolve_root", lambda kind: tmp_path)

    result = discovery.run_scan(
        (fake_spec,), workers=2, include_webkit=False, include_trident=False
    )

    assert len(result.browsers) == 1
    assert result.browsers[0].found is True
    assert len(result.browsers[0].profiles) == 1
    assert len(result.extensions) == 1
    assert result.extensions[0].name == "Discovered Extension"
    assert result.extensions[0].browser == "Fake Chrome"
    assert result.errors == ()


def test_run_scan_reports_not_found_with_roots_checked(tmp_path, monkeypatch):
    fake_spec = BrowserSpec(
        "Never Installed Browser",
        Engine.CHROMIUM,
        "Stable",
        windows=(PathEntry(RootKind.HOME, "does_not_exist"),),
    )
    monkeypatch.setattr(discovery, "resolve_root", lambda kind: tmp_path)

    result = discovery.run_scan(
        (fake_spec,), workers=2, include_webkit=False, include_trident=False
    )

    assert len(result.browsers) == 1
    hit = result.browsers[0]
    assert hit.found is False
    assert hit.profiles == ()
    assert len(hit.roots_checked) == 1  # absence must still be visible (PLAN.md section 14)
    assert result.extensions == ()


def test_expand_candidates_skips_unresolvable_roots(monkeypatch):
    monkeypatch.setattr(discovery, "resolve_root", lambda kind: None)
    spec = BrowserSpec(
        "X", Engine.CHROMIUM, "Stable", windows=(PathEntry(RootKind.WIN_LOCALAPPDATA, "X"),)
    )
    assert discovery.expand_candidates(spec) == []
