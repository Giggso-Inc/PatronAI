"""PLAN.md section 6.1: dependency_version must never state something
false — this is the regression suite for that promise."""

from __future__ import annotations

from ai_sdk_scanner.models import Ecosystem, VersionSpecKind
from ai_sdk_scanner.parsers.base import classify_version_spec


def test_pypi_exact_pin():
    assert classify_version_spec("==1.30.1", Ecosystem.PYPI) == VersionSpecKind.PINNED


def test_pypi_range():
    assert classify_version_spec(">=1.0,<2", Ecosystem.PYPI) == VersionSpecKind.RANGE
    assert classify_version_spec("~=1.0", Ecosystem.PYPI) == VersionSpecKind.RANGE
    assert classify_version_spec(">=1.0", Ecosystem.PYPI) == VersionSpecKind.RANGE


def test_pypi_unpinned():
    assert classify_version_spec("", Ecosystem.PYPI) == VersionSpecKind.UNPINNED
    assert classify_version_spec("*", Ecosystem.PYPI) == VersionSpecKind.UNPINNED


def test_pypi_url():
    assert classify_version_spec(
        "git+https://github.com/openai/openai-python@abc123", Ecosystem.PYPI
    ) == VersionSpecKind.URL


def test_npm_exact_pin():
    assert classify_version_spec("4.20.1", Ecosystem.NPM) == VersionSpecKind.PINNED
    assert classify_version_spec("1.0.0-beta.1", Ecosystem.NPM) == VersionSpecKind.PINNED


def test_npm_caret_and_tilde_are_ranges():
    assert classify_version_spec("^4.20.0", Ecosystem.NPM) == VersionSpecKind.RANGE
    assert classify_version_spec("~4.20.0", Ecosystem.NPM) == VersionSpecKind.RANGE


def test_npm_unpinned():
    assert classify_version_spec("*", Ecosystem.NPM) == VersionSpecKind.UNPINNED
    assert classify_version_spec("latest", Ecosystem.NPM) == VersionSpecKind.UNPINNED
    assert classify_version_spec("workspace:*", Ecosystem.NPM) == VersionSpecKind.UNPINNED


def test_npm_url():
    assert classify_version_spec(
        "git+https://github.com/foo/bar.git", Ecosystem.NPM
    ) == VersionSpecKind.URL
