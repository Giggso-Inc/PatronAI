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
#   v1.1.0  2026-08-31  Add root-process dedup coverage - real Otter (11
#                       processes) and Fathom (5 processes) installs
#                       must collapse to exactly one finding each.
# =============================================================

import re
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


class _FakeSubprocess:
    """Stand-in for the `subprocess` module - returns canned tasklist-shaped
    CSV text instead of touching the real OS process table."""
    DEVNULL = -1

    def __init__(self, output: str):
        self._output = output

    def check_output(self, args, **kwargs):
        return self._output


def _tasklist_line(name: str, pid: int) -> str:
    return f'"{name}","{pid}","Console","1","10,000 K"'


def _run_scan(tasklist_lines: list) -> list:
    """Exec the fragment with a fake Windows tasklist output and run
    scan_processes() end-to-end, including root-process dedup."""
    ns: dict = {
        "re": re, "OS_NAME": "windows",
        "subprocess": _FakeSubprocess("\n".join(tasklist_lines)),
        "_is_authorized": lambda n: False,
    }
    exec(compile((FRAGS / "scan_processes.py.frag").read_text(),
                 "scan_processes.py.frag", "exec"), ns)
    return ns["scan_processes"]()


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


def test_otter_multi_process_collapses_to_one_finding():
    """Real Otter installation produces 11 real OS processes off one
    root (confirmed this session) - must be 1 finding, not 11."""
    pids = [500, 501, 250, 600, 700, 800, 900, 1000, 1100, 1200, 1300]
    lines = [_tasklist_line("Otter.exe", p) for p in pids]
    out = _run_scan(lines)
    otter = [f for f in out if f["name"] == "otter"]
    assert len(otter) == 1
    assert otter[0]["root_pid"] == min(pids)
    assert otter[0]["instance_process_count"] == len(pids)


def test_fathom_multi_process_collapses_to_one_finding():
    """Real Fathom installation produces 5 real OS processes off one
    root (confirmed this session) - must be 1 finding, not 5."""
    pids = [900, 100, 901, 902, 903]
    lines = [_tasklist_line("Fathom.exe", p) for p in pids]
    out = _run_scan(lines)
    fathom = [f for f in out if f["name"] == "fathom"]
    assert len(fathom) == 1
    assert fathom[0]["root_pid"] == min(pids)
    assert fathom[0]["instance_process_count"] == len(pids)


def test_different_app_families_stay_separate_findings():
    lines = [_tasklist_line("Otter.exe", 10), _tasklist_line("Fathom.exe", 20)]
    out = _run_scan(lines)
    assert {f["name"] for f in out} == {"otter", "fathom"}
    assert all(f["instance_process_count"] == 1 for f in out)


def test_processes_scanner_under_loc_cap():
    body = (FRAGS / "scan_processes.py.frag").read_text()
    assert len(body.splitlines()) <= 150
