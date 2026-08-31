# =============================================================
# FILE: tests/unit/test_network_capture_scan.py
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock scan_network_capture.py.frag's contract (D2a2):
#          - no capture file -> [] (Packetbeat is optional, most
#            machines won't have one)
#          - a real TLS SNI record -> a real domain finding
#          - old (outside the scan-window) records are not re-reported
#          - repeated handshakes to the same domain collapse into one
#            finding with a real observation_count, not N duplicates
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial. Real-data regression coverage.
# =============================================================

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


def _tls_line(domain: str, ts: str) -> str:
    return json.dumps({"type": "tls", "@timestamp": ts,
                        "destination": {"ip": "1.2.3.4", "port": 443, "domain": domain}})


def _run_scan(tmp_path: Path, lines: list) -> list:
    agent_dir = tmp_path / ".patronai"
    agent_dir.mkdir()
    if lines:
        (agent_dir / "packetbeat_capture.ndjson").write_text("\n".join(lines), encoding="utf-8")
    ns: dict = {
        "re": re, "os": os, "json": json, "Path": Path,
        "datetime": datetime, "timezone": timezone,
        "AGENT_DIR": agent_dir,
    }
    exec(compile((FRAGS / "scan_network_capture.py.frag").read_text(),
                 "scan_network_capture.py.frag", "exec"), ns)
    return ns["scan_network_capture"]()


def test_no_capture_file_means_no_findings(tmp_path):
    assert _run_scan(tmp_path, []) == []


def test_real_tls_record_produces_a_domain_finding(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    out = _run_scan(tmp_path, [_tls_line("api.anthropic.com", now)])
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "observed_network_target"
    assert f["domain"] == "api.anthropic.com"
    assert f["observation_count"] == 1


def test_old_records_outside_window_are_not_reported(tmp_path):
    """Real capture files accumulate over time - an event from hours ago
    must not be re-reported on every future scan forever."""
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    out = _run_scan(tmp_path, [_tls_line("stale-domain.example.com", old_ts)])
    assert out == []


def test_repeated_handshakes_collapse_to_one_finding_with_real_count(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    lines = [_tls_line("api.anthropic.com", now) for _ in range(5)]
    out = _run_scan(tmp_path, lines)
    matches = [f for f in out if f["domain"] == "api.anthropic.com"]
    assert len(matches) == 1
    assert matches[0]["observation_count"] == 5


def test_non_tls_lines_are_ignored(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        json.dumps({"type": "flow", "@timestamp": now, "destination": {"ip": "1.2.3.4"}}),
        _tls_line("api.anthropic.com", now),
    ]
    out = _run_scan(tmp_path, lines)
    assert len(out) == 1
    assert out[0]["domain"] == "api.anthropic.com"


def test_network_capture_scanner_under_loc_cap():
    body = (FRAGS / "scan_network_capture.py.frag").read_text()
    assert len(body.splitlines()) <= 150
