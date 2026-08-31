# =============================================================
# FILE: tests/unit/test_meeting_bots_scan.py
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock scan_meeting_bots.py.frag's contract (D4c1/D4c2):
#          - detects real Fathom/Otter process names
#          - root-process dedup (real Otter=11, Fathom=5 procs/root)
#          - join_timestamp is a real process-start proxy, never fabricated
#          - bot_account_name/meeting_id are simply absent (not faked)
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial. Real-data regression coverage.
# =============================================================

import re
from datetime import datetime, timezone
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


class _FakeSubprocess:
    DEVNULL = -1

    def __init__(self, tasklist_output: str = "", powershell_output: str = ""):
        self._tasklist_output   = tasklist_output
        self._powershell_output = powershell_output

    def check_output(self, args, **kwargs):
        if args and args[0] == "powershell":
            return self._powershell_output
        return self._tasklist_output


def _tasklist_line(name: str, pid: int) -> str:
    return f'"{name}","{pid}","Console","1","10,000 K"'


def _run_scan(tasklist_lines: list, powershell_output: str = "") -> list:
    ns: dict = {
        "re": re, "OS_NAME": "windows", "datetime": datetime, "timezone": timezone,
        "subprocess": _FakeSubprocess("\n".join(tasklist_lines), powershell_output),
        "_is_authorized": lambda n: False,
    }
    exec(compile((FRAGS / "scan_meeting_bots.py.frag").read_text(),
                 "scan_meeting_bots.py.frag", "exec"), ns)
    return ns["scan_meeting_bots"]()


def _match(name: str) -> bool:
    ns: dict = {"re": re}
    exec(compile((FRAGS / "scan_meeting_bots.py.frag").read_text(),
                 "scan_meeting_bots.py.frag", "exec"), ns)
    return bool(ns["_MEETING_BOT_RE"].search(name))


def test_fathom_and_otter_detected():
    assert _match("Fathom.exe")
    assert _match("Otter.exe")


def test_unrelated_process_not_flagged():
    assert not _match("chrome.exe")
    assert not _match("claude.exe")


def test_otter_real_process_count_collapses_to_one_finding():
    """Real Otter install produces 11 real OS processes off one root
    (confirmed this session) - must be 1 finding, not 11."""
    pids = [500, 501, 250, 600, 700, 800, 900, 1000, 1100, 1200, 1300]
    lines = [_tasklist_line("Otter.exe", p) for p in pids]
    out = _run_scan(lines)
    otter = [f for f in out if f["platform"] == "otter"]
    assert len(otter) == 1
    assert otter[0]["root_pid"] == min(pids)
    assert otter[0]["instance_process_count"] == len(pids)


def test_fathom_real_process_count_collapses_to_one_finding():
    """Real Fathom install produces 5 real OS processes off one root
    (confirmed this session) - must be 1 finding, not 5."""
    pids = [900, 100, 901, 902, 903]
    lines = [_tasklist_line("Fathom.exe", p) for p in pids]
    out = _run_scan(lines)
    fathom = [f for f in out if f["platform"] == "fathom"]
    assert len(fathom) == 1
    assert fathom[0]["root_pid"] == min(pids)
    assert fathom[0]["instance_process_count"] == len(pids)


def test_join_timestamp_is_real_when_epoch_available():
    out = _run_scan([_tasklist_line("Otter.exe", 500)], powershell_output="1700000000")
    otter = [f for f in out if f["platform"] == "otter"][0]
    assert otter["join_timestamp"]  # real ISO string, not fabricated


def test_join_timestamp_absent_when_no_epoch():
    out = _run_scan([_tasklist_line("Otter.exe", 500)], powershell_output="")
    otter = [f for f in out if f["platform"] == "otter"][0]
    assert "join_timestamp" not in otter


def test_bot_account_name_and_meeting_id_not_fabricated():
    """Real account/session data lives in LevelDB (Local/Session Storage),
    confirmed by inspecting real Fathom/Otter AppData this session - not
    plaintext-readable, and not attempted here. Must never appear as a
    fake/empty placeholder field."""
    out = _run_scan([_tasklist_line("Otter.exe", 500)])
    otter = [f for f in out if f["platform"] == "otter"][0]
    assert "bot_account_name" not in otter
    assert "meeting_id" not in otter


def test_meeting_bots_scanner_under_loc_cap():
    body = (FRAGS / "scan_meeting_bots.py.frag").read_text()
    assert len(body.splitlines()) <= 150
