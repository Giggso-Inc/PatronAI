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
#   v1.2.0  2026-08-31  Add session_duration_seconds / start_timestamp
#                       coverage (Autonomous AI Agents D4b1/D4b2).
#   v1.3.0  2026-08-31  Fathom/Otter moved to their own category
#                       (scan_meeting_bots.py.frag / D4c1-D4c2) - dedup
#                       tests here now use claude as the multi-process
#                       stand-in instead. See test_meeting_bots_scan.py
#                       for the Fathom/Otter coverage.
# =============================================================

import re
from datetime import datetime, timezone
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


class _FakeSubprocess:
    """Stand-in for the `subprocess` module. Routes to different canned
    output depending on whether the fragment is calling tasklist (process
    enumeration) or powershell (start-epoch lookup) - real code calls both."""
    DEVNULL = -1

    def __init__(self, tasklist_output: str = "", powershell_output: str = ""):
        self._tasklist_output  = tasklist_output
        self._powershell_output = powershell_output

    def check_output(self, args, **kwargs):
        if args and args[0] == "powershell":
            return self._powershell_output
        return self._tasklist_output


def _tasklist_line(name: str, pid: int) -> str:
    return f'"{name}","{pid}","Console","1","10,000 K"'


def _run_scan(tasklist_lines: list, powershell_lines: list = None) -> list:
    """Exec the fragment with fake Windows tasklist/powershell output and
    run scan_processes() end-to-end, including root-process dedup and
    session-duration lookup."""
    ns: dict = {
        "re": re, "OS_NAME": "windows", "datetime": datetime, "timezone": timezone,
        "subprocess": _FakeSubprocess("\n".join(tasklist_lines),
                                       "\n".join(powershell_lines or [])),
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


def test_system_processes_not_falsely_flagged():
    for name in ("explorer.exe", "svchost.exe", "sihost.exe", "chrome.exe"):
        assert not _match(name), f"{name} should not match"


def test_fathom_and_otter_no_longer_match_here():
    """Recategorized into scan_meeting_bots.py.frag (D4c1/D4c2) - must
    NOT also match the generic bucket, or the same app double-counts
    under two finding types."""
    assert not _match("Fathom.exe")
    assert not _match("Otter.exe")


def test_multi_process_family_collapses_to_one_finding():
    """Same real shape as a multi-process app (e.g. Otter's real 11
    processes) - must be 1 finding, not N."""
    pids = [500, 501, 250, 600, 700, 800, 900, 1000, 1100, 1200, 1300]
    lines = [_tasklist_line("claude.exe", p) for p in pids]
    out = _run_scan(lines)
    claude = [f for f in out if f["name"] == "claude"]
    assert len(claude) == 1
    assert claude[0]["root_pid"] == min(pids)
    assert claude[0]["instance_process_count"] == len(pids)


def test_different_app_families_stay_separate_findings():
    lines = [_tasklist_line("claude.exe", 10), _tasklist_line("PAD.AutomationServer.exe", 20)]
    out = _run_scan(lines)
    assert {f["name"] for f in out} == {"claude", "pad.automationserver"}
    assert all(f["instance_process_count"] == 1 for f in out)


def test_session_duration_computed_from_real_start_epoch():
    """A root process that started 1 real hour ago must report a
    session_duration_seconds close to 3600, and a real ISO start_timestamp."""
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    one_hour_ago = now_epoch - 3600
    lines = [_tasklist_line("claude.exe", 500)]
    ps_lines = [f"500,{one_hour_ago}"]
    out = _run_scan(lines, ps_lines)
    claude = [f for f in out if f["name"] == "claude"][0]
    assert 3595 <= claude["session_duration_seconds"] <= 3610
    assert claude["start_timestamp"]  # a real ISO string, not empty


def test_session_duration_absent_when_os_gives_no_epoch():
    """If the epoch lookup can't find this PID (or fails entirely), the
    finding must not fabricate a duration - fields are simply omitted."""
    out = _run_scan([_tasklist_line("claude.exe", 500)], powershell_lines=[])
    claude = [f for f in out if f["name"] == "claude"][0]
    assert "session_duration_seconds" not in claude
    assert "start_timestamp" not in claude


def test_processes_scanner_under_loc_cap():
    body = (FRAGS / "scan_processes.py.frag").read_text()
    assert len(body.splitlines()) <= 150
