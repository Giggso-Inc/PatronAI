# =============================================================
# FILE: tests/unit/test_processes_scan.py
# PROJECT: PatronAI — Phase 1A
# VERSION: 1.0.0
# UPDATED: 2026-08-28
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock the process scanner's regex contract against real AI
#          tool process names captured live off a real machine this
#          session (claude, Power Automate Desktop, Fathom, Otter were
#          confirmed 0/31 detected before this fix).
# AUDIT LOG:
#   v1.0.0  2026-08-28  Initial. Real-data regression coverage.
# =============================================================

import re
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


def _match(name: str) -> bool:
    ns: dict = {"re": re, "_is_authorized": lambda n: False}
    exec(compile((FRAGS / "scan_processes.py.frag").read_text(),
                 "scan_processes.py.frag", "exec"), ns)
    return bool(ns["_AI_PROCS_RE"].search(name))


def test_claude_desktop_and_cli_detected():
    assert _match("claude.exe")
    assert _match("claude")


def test_power_automate_desktop_detected():
    assert _match("PAD.Console.Host.exe")
    assert _match("PAD.AutomationServer.exe")


def test_fathom_and_otter_detected():
    assert _match("Fathom.exe")
    assert _match("Otter.exe")


def test_system_processes_not_falsely_flagged():
    for name in ("explorer.exe", "svchost.exe", "sihost.exe", "chrome.exe"):
        assert not _match(name), f"{name} should not match"


def test_processes_scanner_under_loc_cap():
    body = (FRAGS / "scan_processes.py.frag").read_text()
    assert len(body.splitlines()) <= 150
