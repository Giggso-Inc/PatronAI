# =============================================================
# FILE: tests/unit/test_vector_db_ports_scan.py
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock scan_vector_db_ports.py.frag's contract (D2c1/D2c2,
#          additive to the file-signature scanner per team decision):
#          - real listening port -> finding, tagged source=listening_port
#          - no listening port -> no finding (never guesses)
#          - a matching `docker ps` entry -> container_id/image populated
#          - no matching container -> both empty, not fabricated
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial. Real-data regression coverage.
# =============================================================

import re
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


class _FakeSubprocess:
    """Routes to netstat or docker canned output depending on the call."""
    DEVNULL = -1

    def __init__(self, netstat_output: str = "", docker_output: str = ""):
        self._netstat_output = netstat_output
        self._docker_output  = docker_output

    def check_output(self, args, **kwargs):
        if args and args[0] == "docker":
            return self._docker_output
        return self._netstat_output


def _win_listen_line(port: int) -> str:
    return f"  TCP    0.0.0.0:{port}            0.0.0.0:0              LISTENING"


def _run_scan(netstat_output: str = "", docker_output: str = "") -> list:
    ns: dict = {
        "re": re, "OS_NAME": "windows",
        "subprocess": _FakeSubprocess(netstat_output, docker_output),
    }
    exec(compile((FRAGS / "scan_vector_db_ports.py.frag").read_text(),
                 "scan_vector_db_ports.py.frag", "exec"), ns)
    return ns["scan_vector_db_ports"]()


def test_no_listening_ports_means_no_findings():
    assert _run_scan(netstat_output="") == []


def test_real_qdrant_port_listening_produces_finding():
    out = _run_scan(netstat_output=_win_listen_line(6333))
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "vector_db"
    assert f["kind"] == "qdrant"
    assert f["source"] == "listening_port"
    assert f["listening_port"] == 6333


def test_unrelated_port_listening_is_not_flagged():
    out = _run_scan(netstat_output=_win_listen_line(3389))  # RDP, not a vector DB
    assert out == []


def test_multiple_known_ports_each_get_a_finding():
    lines = "\n".join([_win_listen_line(6333), _win_listen_line(8000)])
    out = _run_scan(netstat_output=lines)
    kinds = {f["kind"] for f in out}
    assert kinds == {"qdrant", "chroma"}


def test_container_id_populated_when_docker_ps_matches():
    docker_out = "abc123\tqdrant/qdrant\t0.0.0.0:6333->6333/tcp, 0.0.0.0:6334->6334/tcp"
    out = _run_scan(netstat_output=_win_listen_line(6333), docker_output=docker_out)
    f = out[0]
    assert f["container_id"] == "abc123"
    assert f["container_image"] == "qdrant/qdrant"


def test_container_fields_empty_when_no_docker_match():
    """Real bare-metal (non-Docker) instance - must not fabricate a
    container_id just because the port matched."""
    out = _run_scan(netstat_output=_win_listen_line(6333), docker_output="")
    f = out[0]
    assert f["container_id"] == ""
    assert f["container_image"] == ""


def test_vector_db_ports_scanner_under_loc_cap():
    body = (FRAGS / "scan_vector_db_ports.py.frag").read_text()
    assert len(body.splitlines()) <= 150
