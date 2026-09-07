# =============================================================
# FILE: agent/capture/capture_service.py
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Boot-start, long-running half of the capture companion.
#          Captures packets, converts closed segments to JSONL via
#          pktmon_to_jsonl.py, seals them into the spool. Uploading is
#          sync_task.py's job, not this one's.
# DEPENDS: stdlib ONLY (common.py explains why).
# =============================================================
"""Continuous capture -> spool. Runs elevated, from boot.

Per-OS capture is the ONLY OS-specific part; the parser is portable and
consumes pcapng regardless of how it was produced:

  Windows  pktmon (built into Windows 10 1809+) -> .etl -> etl2pcap -> .pcapng
  macOS    dumpcap (ships with Wireshark) -> .pcapng directly
  Linux    dumpcap -> .pcapng directly

Only Windows needs the .etl staging step; the others drop it entirely.

Nothing is deleted until the next stage has succeeded: a segment's raw files
go only after its records are safely in the spool, and a spool file only
after sync_task confirms the upload.

Self-test:  python capture_service.py --selftest
"""
import argparse
import gzip
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import common
import pktmon_to_jsonl

SEGMENT_SECONDS = int(os.environ.get("PATRONAI_SEGMENT_SECONDS", 3600))
HERE = Path(__file__).resolve().parent

_stop = False


# Writes the log file itself rather than relying on the scheduled task's
# cmd.exe redirect - see common.make_logger for why that mattered.
log = common.make_logger("capture")


def _handle_stop(signum, frame):
    global _stop
    _stop = True
    log(f"signal {signum} - finishing the current segment then exiting")


# ── Naming ───────────────────────────────────────────────────────────────

def new_run_id() -> str:
    """8 hex chars, regenerated on every service start.

    Not decoration: pktmon restarts its own file numbering at 1 on every
    capture session, so a second run recreated names an earlier run's
    processed-log had already seen. Every new segment was skipped as
    "already done" and the JSONL silently stopped growing, with no error
    anywhere. A per-session id makes that collision impossible.
    """
    return uuid.uuid4().hex[:8]


def spool_name(run_id: str, seq: int, when: datetime = None) -> str:
    """20260901T141503Z-7b2e9f04-0001.jsonl.gz

    Identical to the final S3 object basename, so the key is re-derivable
    from the file alone and a re-upload after a failed delete lands on
    exactly the same key.
    """
    when = when or datetime.now(timezone.utc)
    return f"{when.strftime('%Y%m%dT%H%M%SZ')}-{run_id}-{seq:04d}.jsonl.gz"


def next_seq() -> int:
    """Monotonic, persisted - a crash must never reuse a sequence number."""
    seq = common.read_counter("seq") + 1
    common.write_counter("seq", seq)
    return seq


# ── Per-OS capture ───────────────────────────────────────────────────────

def start_capture(capture_dir: Path, run_id: str) -> subprocess.Popen:
    """Begin capturing. Returns the child process, or None on Windows where
    pktmon is a system service driven by start/stop rather than a child."""
    system = platform.system()
    if system == "Windows":
        subprocess.run(
            ["pktmon", "start", "--capture", "--pkt-size", "0",
             "-m", "multi-file", "--file-name",
             str(capture_dir / f"seg_{run_id}.etl")],
            check=True, capture_output=True)
        return None
    # dumpcap ships with Wireshark, which the installer puts on the box
    # anyway for tshark - so macOS/Linux need no extra dependency.
    return subprocess.Popen(
        ["dumpcap", "-i", "any", "-q",
         "-b", f"duration:{SEGMENT_SECONDS}",
         "-w", str(capture_dir / f"seg_{run_id}.pcapng")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_capture(proc: subprocess.Popen) -> None:
    if platform.system() == "Windows":
        subprocess.run(["pktmon", "stop"], capture_output=True)
    elif proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()


def closed_segments(capture_dir: Path, run_id: str) -> list:
    """Rotated-out segments for THIS run, oldest first.

    Scoped to run_id deliberately: leftover files from an earlier session are
    ignored rather than re-ingested, because re-ingesting would duplicate
    records already in the spool.

    The newest file is skipped - it is the one still being written to.
    """
    pattern = f"seg_{run_id}*"
    segs = sorted(
        (f for f in capture_dir.glob(pattern)
         if f.suffix in (".etl", ".pcapng")),
        key=lambda f: f.name)
    return segs[:-1] if segs else []


def to_pcapng(segment: Path) -> Path:
    """Windows .etl -> .pcapng. A no-op everywhere else."""
    if segment.suffix != ".etl":
        return segment
    out = segment.with_suffix(".pcapng")
    subprocess.run(["pktmon", "etl2pcap", str(segment), "--out", str(out)],
                   check=True, capture_output=True)
    segment.unlink(missing_ok=True)   # raw .etl goes only once converted
    return out


# ── Segment -> spool ─────────────────────────────────────────────────────

def process_segment(segment: Path, paths: dict, run_id: str) -> Path:
    """One closed segment -> one sealed spool file. Returns its path, or None.

    The parser runs as a SUBPROCESS rather than an import so that main()'s
    policy choke point is reused exactly as written - reimplementing the
    pipeline here would be a second place for the data policy to be wrong.
    It also keeps a parser crash from taking down the service.
    """
    pcapng = to_pcapng(segment)
    raw_out = paths["capture"] / (pcapng.stem + ".jsonl")
    keylog = paths["keylog"] / "sslkeys.log"

    result = subprocess.run(
        [sys.executable, str(HERE / "pktmon_to_jsonl.py"),
         "--pcap", str(pcapng), "--keylog", str(keylog), "--out", str(raw_out)],
        capture_output=True, text=True)
    if result.returncode != 0:
        log(f"extract failed for {pcapng.name}: {result.stderr.strip()[:300]}")
        return None   # raw is KEPT - a failed extract must not lose data

    try:
        data = raw_out.read_bytes()
        if not data.strip():
            log(f"{pcapng.name}: no records extracted")
        else:
            target = paths["spool"] / spool_name(run_id, next_seq())
            common.write_atomic(target, gzip.compress(data))
            log(f"{pcapng.name} -> {target.name} ({len(data)} bytes raw)")
            return target
    finally:
        raw_out.unlink(missing_ok=True)
        pcapng.unlink(missing_ok=True)   # safe now: records are in the spool
    return None


# ── Entry point ──────────────────────────────────────────────────────────

def preflight() -> None:
    """Refuse to start rather than run half-broken."""
    common.require_integrity(logger=log)

    missing = pktmon_to_jsonl.verify_tshark_fields()
    if missing:
        raise SystemExit(
            "tshark is missing fields this parser needs: "
            + ", ".join(missing)
            + ". Extraction would return zero rows and exit 0 - refusing to start.")
    log(f"tshark: all {len(pktmon_to_jsonl.ALL_TSHARK_FIELDS)} required fields present")

    if platform.system() != "Windows" and not shutil.which("dumpcap"):
        raise SystemExit("dumpcap not found on PATH - install Wireshark and retry.")


def run() -> None:
    preflight()
    paths = common.ensure_dirs()
    run_id = new_run_id()
    common.write_atomic(paths["state"] / "run_id", run_id.encode("utf-8"))
    # Be honest about what actually drives rotation on this platform.
    # SEGMENT_SECONDS only applies to the dumpcap path; pktmon rotates on SIZE
    # and ignores it entirely, so printing "segment=3600s" on Windows claimed a
    # cadence that does not exist. Measured on a real machine: a segment closes
    # roughly every 9 minutes under active use, and not at all on an idle one.
    if platform.system() == "Windows":
        log(f"starting - run_id={run_id} rotation=pktmon size-based "
            f"(SEGMENT_SECONDS not applicable)")
    else:
        log(f"starting - run_id={run_id} rotation={SEGMENT_SECONDS}s (dumpcap)")

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    proc = start_capture(paths["capture"], run_id)
    try:
        while not _stop:
            for segment in closed_segments(paths["capture"], run_id):
                process_segment(segment, paths, run_id)
            time.sleep(30)
    finally:
        stop_capture(proc)
        # The final segment is only closed by stop_capture, so it has to be
        # picked up AFTER stopping - the POC lost this one on every shutdown
        # until a final pass was added here.
        for segment in sorted(paths["capture"].glob(f"seg_{run_id}*")):
            if segment.suffix in (".etl", ".pcapng"):
                process_segment(segment, paths, run_id)
        log("stopped")


def _selftest():
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="patronai-capture-svc-selftest-"))
    os.environ["PATRONAI_CAPTURE_DIR"] = str(tmp)
    try:
        paths = common.ensure_dirs()

        # run_id is hex and 8 chars - sync_task's filename regex requires it.
        rid = new_run_id()
        assert len(rid) == 8 and all(c in "0123456789abcdef" for c in rid), rid

        # Spool name matches the contract sync_task parses.
        when = datetime(2026, 9, 1, 14, 15, 3, tzinfo=timezone.utc)
        name = spool_name("7b2e9f04", 1, when)
        assert name == "20260901T141503Z-7b2e9f04-0001.jsonl.gz", name
        import sync_task
        assert sync_task.SPOOL_NAME_RE.match(name), "capture and sync must agree on naming"
        assert sync_task.s3_key_for(name, "tok").endswith(name)

        # Sequence is monotonic and persisted.
        assert next_seq() == 1 and next_seq() == 2
        assert common.read_counter("seq") == 2

        # Segment discovery: newest is skipped (still being written), other
        # runs' files are ignored so they are never re-ingested.
        for n in ["seg_7b2e9f04_1.pcapng", "seg_7b2e9f04_2.pcapng",
                  "seg_7b2e9f04_3.pcapng", "seg_deadbeef_1.pcapng"]:
            (paths["capture"] / n).write_bytes(b"x")
        found = [f.name for f in closed_segments(paths["capture"], "7b2e9f04")]
        assert found == ["seg_7b2e9f04_1.pcapng", "seg_7b2e9f04_2.pcapng"], found

        # A single segment is entirely "still being written" - nothing to do.
        (paths["capture"] / "seg_cafebabe_1.pcapng").write_bytes(b"x")
        assert closed_segments(paths["capture"], "cafebabe") == []

        print("capture_service self-test: PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        _selftest()
        return
    run()


if __name__ == "__main__":
    main()
