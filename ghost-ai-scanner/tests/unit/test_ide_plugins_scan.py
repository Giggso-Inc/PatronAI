# =============================================================
# FILE: tests/unit/test_ide_plugins_scan.py
# PROJECT: PatronAI — Phase 1A
# VERSION: 1.0.0
# UPDATED: 2026-08-28
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock the IDE-plugin scanner's regex contract against real
#          installed extension IDs captured live this session (0/7
#          detected before this fix — publisher-prefix mismatch on
#          Amazon Q, claude-code missing entirely).
# AUDIT LOG:
#   v1.0.0  2026-08-28  Initial. Real-data regression coverage.
# =============================================================

import re
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


def _match(plugin_id: str) -> bool:
    ns: dict = {"re": re}
    exec(compile((FRAGS / "scan_ide_plugins.py.frag").read_text(),
                 "scan_ide_plugins.py.frag", "exec"), ns)
    return bool(ns["_AI_IDE_PLUGINS_RE"].search(plugin_id))


def test_claude_code_detected():
    assert _match("anthropic.claude-code-2.1.245-win32-x64".rsplit("-", 1)[0].lower())


def test_amazon_q_real_publisher_id_detected():
    # Real published extension ID uses the amazonwebservices prefix, not aws.
    assert _match("amazonwebservices.amazon-q-vscode-2.6.0".rsplit("-", 1)[0].lower())


def test_old_wrong_aws_prefix_no_longer_the_only_match():
    # The old (wrong) pattern must not be required for a match to occur —
    # the real ID alone (amazonwebservices.*) is sufficient.
    assert _match("amazonwebservices.amazon-q-vscode")


def test_unrelated_extension_not_flagged():
    assert not _match("dbaeumer.vscode-eslint")


def test_ide_plugins_scanner_under_loc_cap():
    body = (FRAGS / "scan_ide_plugins.py.frag").read_text()
    assert len(body.splitlines()) <= 150
