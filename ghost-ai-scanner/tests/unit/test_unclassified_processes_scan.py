# =============================================================
# FILE: tests/unit/test_unclassified_processes_scan.py
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock scan_unclassified_processes.py.frag's contract:
#          - a genuinely unknown process (not in any AI catalog, not an
#            OS process) -> a real LOW-severity finding
#          - known OS/system processes -> never flagged
#          - a process already caught by an AI-specific category ->
#            not double-counted here too
#          - an authorized (org allowlisted) process -> suppressed
#          - multi-process apps still collapse to one finding (root-pid dedup)
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial. Real-data regression coverage.
# =============================================================

import re
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


def _tasklist_line(name: str, pid: int) -> str:
    return f'"{name}","{pid}","Console","1","10,000 K"'


def _run_scan(tasklist_lines: list, authorized=None, ai_re=None, meeting_re=None) -> list:
    """Exec the fragment with fake process records and the same
    cross-fragment globals it relies on in the real pipeline
    (_AI_PROCS_RE / _MEETING_BOT_RE / _is_authorized / _process_records)."""
    records = []
    for ln in tasklist_lines:
        parts = [p.strip('"') for p in ln.split(",")]
        records.append((int(parts[1]), parts[0]))

    ns: dict = {
        "re": re,
        "_process_records": lambda: records,
        "_is_authorized": (lambda n: n in authorized) if authorized else (lambda n: False),
    }
    if ai_re is not None:
        ns["_AI_PROCS_RE"] = ai_re
    if meeting_re is not None:
        ns["_MEETING_BOT_RE"] = meeting_re
    exec(compile((FRAGS / "scan_unclassified_processes.py.frag").read_text(),
                 "scan_unclassified_processes.py.frag", "exec"), ns)
    return ns["scan_unclassified_processes"]()


def test_unknown_process_is_flagged():
    out = _run_scan([_tasklist_line("SomeBrandNewAiTool.exe", 500)])
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "unclassified_software"
    assert f["name"] == "SomeBrandNewAiTool.exe"  # real casing preserved; dedup key is lowercased


def test_known_os_processes_never_flagged():
    lines = [_tasklist_line(n, i) for i, n in enumerate(
        ["explorer.exe", "svchost.exe", "System", "dwm.exe", "conhost.exe"], start=100)]
    assert _run_scan(lines) == []


def test_linux_kworker_threads_never_flagged():
    out = _run_scan([_tasklist_line("kworker/0:1", 7)])
    assert out == []


def test_already_ai_matched_process_not_double_counted():
    """A process the dedicated AI-category fragments already caught
    must not ALSO show up in the generic unclassified bucket."""
    ai_re = re.compile(r"\bclaude\b", re.IGNORECASE)
    out = _run_scan([_tasklist_line("claude.exe", 500)], ai_re=ai_re)
    assert out == []


def test_meeting_bot_matched_process_not_double_counted():
    meeting_re = re.compile(r"\botter\b", re.IGNORECASE)
    out = _run_scan([_tasklist_line("Otter.exe", 500)], meeting_re=meeting_re)
    assert out == []


def test_authorized_process_is_suppressed():
    out = _run_scan([_tasklist_line("InternalTool.exe", 500)],
                     authorized={"internaltool.exe"})
    assert out == []


def test_multi_process_unknown_app_collapses_to_one_finding():
    pids = [500, 250, 600, 700]
    lines = [_tasklist_line("NewTool.exe", p) for p in pids]
    out = _run_scan(lines)
    assert len(out) == 1
    assert out[0]["root_pid"] == min(pids)
    assert out[0]["instance_process_count"] == len(pids)


def test_unclassified_processes_scanner_under_loc_cap():
    body = (FRAGS / "scan_unclassified_processes.py.frag").read_text()
    assert len(body.splitlines()) <= 150
