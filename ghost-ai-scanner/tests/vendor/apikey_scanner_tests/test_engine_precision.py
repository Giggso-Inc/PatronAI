"""Precision corpus: lines that must NOT produce a finding. PLAN.md
section 11.3 -- guards the section 5 false-positive filters against
regression.
"""

from __future__ import annotations

import pytest

from apikey_scanner.detect.engine import scan_line

NON_SECRET_LINES = [
    # Placeholders
    'api_key = "your_api_key_here_1234567890"',
    'token = "changeme_1234567890123456"',
    'secret = "REDACTED_1234567890123456"',
    # Indirection -- the correct pattern, must never be flagged
    'api_key = os.environ["API_KEY"]',
    "token = ${SECRET_TOKEN}",
    'password = config.get("db_password")',
    # Structural non-secrets
    'integrity = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="',
    'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA"',
    # Sequential / repeated-char runs
    'api_key = "abcdefghijklmnopqrstuvwx"',
    'secret_token = "AAAAAAAAAAAAAAAAAAAAAAAA"',
    # Plain code with no secret-shaped content at all
    "def calculate_total(items):",
    "    return sum(item.price for item in items)",
    'logger.info("request completed in %s ms", elapsed_ms)',
]


@pytest.mark.parametrize("line", NON_SECRET_LINES)
def test_line_produces_no_findings(line, catalog, base_config):
    detections = scan_line(line, 1, catalog, base_config, is_lockfile=False)
    assert detections == [], f"unexpected finding(s) on: {line!r} -> {detections}"


def test_lockfile_suppresses_low_and_medium_confidence(catalog, base_config):
    # A low-confidence generic entropy-shaped assignment inside a lockfile
    # must not fire even though it would fire in an ordinary source file.
    line = 'integrity_key = "aK3x9QmZ7pL2vN8sT1wY0bR4cD6fH2jM5nP8qS1uW3yZ"'
    assert scan_line(line, 1, catalog, base_config, is_lockfile=True) == []
    assert scan_line(line, 1, catalog, base_config, is_lockfile=False) != []


def test_long_line_is_skipped_entirely(catalog, base_config):
    line = ('x = "' + "a" * 6000) + '"'
    assert scan_line(line, 1, catalog, base_config, is_lockfile=False) == []
