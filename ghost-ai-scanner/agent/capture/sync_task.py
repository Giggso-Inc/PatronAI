# =============================================================
# FILE: agent/capture/sync_task.py
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Scheduled task - size check, upload the spool to S3, verify,
#          delete. Short-lived: runs, drains what it can, exits.
#          The long-running half is capture_service.py.
# DEPENDS: stdlib ONLY (common.py explains why).
# =============================================================
"""Hourly sync of the capture spool to S3.

Delivery contract:
  * A spool file is deleted ONLY after the upload is confirmed - HTTP 2xx AND
    the returned ETag matching the locally computed MD5.
  * If the upload succeeded but the delete did not, the next run re-uploads
    the same key with byte-identical content. Overwriting an object with the
    same bytes is harmless, so at-least-once delivery is safe by construction
    and needs no dedup logic anywhere.
  * Past the disk ceiling with sync still failing, the OLDEST spool files are
    dropped and COUNTED. A silent drop is a bug, not a degradation.

Self-test:  python sync_task.py --selftest
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

import common
import uploader

# Combined ceiling for capture/ + spool/. An outage backstop, not a routine
# limit: at ~2.5 MB/device/day gzipped this is years of backlog, and under
# hourly sync it should never be approached.
DISK_CEILING_BYTES = int(os.environ.get("PATRONAI_DISK_CEILING", 3 * 1024 ** 3))

# Spool basenames look like 20260901T141503Z-7b2e9f04-0001.jsonl.gz
SPOOL_NAME_RE = re.compile(
    r"^(?P<ts>\d{8}T\d{6}Z)-(?P<run>[0-9a-f]+)-(?P<seq>\d+)\.jsonl\.gz$")


# Writes the log file itself rather than relying on the scheduled task's
# cmd.exe redirect - see common.make_logger for why that mattered.
log = common.make_logger("sync")


# ── Key derivation ───────────────────────────────────────────────────────

def s3_key_for(basename: str, token: str) -> str:
    """ocsf/tshark/{token}/{YYYY}/{MM}/{DD}/{HH}/{basename}

    The partition comes from the filename's own timestamp, so the key is
    fully re-derivable from the file alone - which is what makes re-upload
    after a failed delete produce the identical key.

    NOTE the partition is the batch's SEAL hour, not the hour its records
    happened. A capture segment straddling an hour boundary files earlier
    records under a later partition. The partition exists for cheap listing;
    consumers must read time from each record's own `timestamp` field.
    """
    m = SPOOL_NAME_RE.match(basename)
    if not m:
        raise ValueError(f"unrecognised spool filename: {basename}")
    ts = m.group("ts")
    return (f"ocsf/tshark/{token}/{ts[0:4]}/{ts[4:6]}/{ts[6:8]}/{ts[9:11]}/{basename}")


# ── Multipart POST, stdlib only ──────────────────────────────────────────

def upload(path: Path, token: str, post: dict, timeout: int = 120) -> bool:
    """Upload one spool file. True only when the object is confirmed stored.

    The transport itself lives in uploader.py, which BOTH agents use - so a
    new storage backend is one change in one file rather than a hunt through
    every agent. This function keeps only what is specific to capture: which
    key the file belongs at.
    """
    try:
        uploader.upload_post(post, s3_key_for(path.name, token),
                             path.read_bytes(), "application/gzip", timeout)
        return True
    except uploader.UploadError as exc:
        # Log and return False rather than raise: a failed upload must leave
        # the spool file in place for the next cycle, never lose it.
        log(str(exc))
        return False


# ── Backpressure ─────────────────────────────────────────────────────────

def spool_files(spool: Path) -> list:
    """Spool files, oldest first. Anything not matching the naming contract
    is ignored rather than uploaded - an unrecognised name means we cannot
    derive a key for it, and guessing is worse than leaving it alone."""
    return sorted((f for f in spool.glob("*.jsonl.gz") if SPOOL_NAME_RE.match(f.name)),
                  key=lambda f: f.name)


def record_drops(n: int, bytes_freed: int) -> None:
    """Accumulate drop counts for the heartbeat. Dropping data silently is
    the one thing this design refuses to do."""
    f = common.paths()["state"] / "drops.json"
    try:
        state = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {"dropped_files": 0, "dropped_bytes": 0, "last_drop": None}
    state["dropped_files"] += n
    state["dropped_bytes"] += bytes_freed
    state["last_drop"] = datetime.now(timezone.utc).isoformat()
    common.write_atomic(f, json.dumps(state, indent=2).encode("utf-8"))
    log(f"DROPPED {n} spool file(s), {bytes_freed} bytes - sync is failing and disk is full")


def enforce_ceiling(paths: dict, ceiling: int = DISK_CEILING_BYTES) -> int:
    """Drop oldest spool files until under the ceiling. Returns files dropped.

    Only reached when sync has already failed - the normal path is that
    uploads drain the spool long before this matters.
    """
    used = common.dir_size(paths["capture"]) + common.dir_size(paths["spool"])
    if used <= ceiling:
        return 0
    dropped = freed = 0
    for f in spool_files(paths["spool"]):
        if used <= ceiling:
            break
        size = f.stat().st_size
        f.unlink(missing_ok=True)
        used -= size
        freed += size
        dropped += 1
    if dropped:
        record_drops(dropped, freed)
    return dropped


# ── Entry point ──────────────────────────────────────────────────────────

def run_once() -> dict:
    common.require_integrity(logger=log)
    paths = common.ensure_dirs()
    cfg = common.load_config()
    token = cfg["token"]

    post = common.load_urls().get("capture_post", {})
    if not post.get("url"):
        log("no capture_post policy in urls.json - cannot upload this cycle")
        # Still enforce the ceiling: a missing URL is exactly the outage the
        # backstop exists for.
        return {"uploaded": 0, "failed": 0, "dropped": enforce_ceiling(paths)}

    uploaded = failed = 0
    for f in spool_files(paths["spool"]):
        if upload(f, token, post):
            f.unlink(missing_ok=True)
            uploaded += 1
        else:
            failed += 1

    dropped = enforce_ceiling(paths)
    status = {
        "uploaded": uploaded, "failed": failed, "dropped": dropped,
        "spool_bytes": common.dir_size(paths["spool"]),
        "capture_bytes": common.dir_size(paths["capture"]),
        "at": datetime.now(timezone.utc).isoformat(),
    }
    common.write_atomic(paths["state"] / "sync_status.json",
                        json.dumps(status, indent=2).encode("utf-8"))
    log(f"uploaded={uploaded} failed={failed} dropped={dropped} "
        f"spool={status['spool_bytes']}B")
    return status


def _selftest():
    import shutil
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="patronai-sync-selftest-"))
    os.environ["PATRONAI_CAPTURE_DIR"] = str(tmp)
    try:
        paths = common.ensure_dirs()

        # Key derivation: partition comes from the filename's timestamp.
        key = s3_key_for("20260901T141503Z-7b2e9f04-0001.jsonl.gz", "a3f9c1e2")
        assert key == ("ocsf/tshark/a3f9c1e2/2026/09/01/14/"
                       "20260901T141503Z-7b2e9f04-0001.jsonl.gz"), key

        # A name we cannot parse must raise, never produce a guessed key.
        try:
            s3_key_for("garbage.jsonl.gz", "tok")
            raise AssertionError("expected ValueError on unparseable name")
        except ValueError:
            pass

        # Transport is uploader.py's job now; verify the wiring, and that a
        # missing policy fails CLOSED (never deletes an un-uploaded file).
        assert uploader.upload_post is not None
        from pathlib import Path as _P
        probe = paths["spool"] / "20260901T000000Z-7b2e9f04-9999.jsonl.gz"
        probe.write_bytes(b"x")
        assert upload(probe, "tok", {}) is False, "no policy must fail, not silently pass"
        assert probe.exists(), "a failed upload must leave the spool file in place"
        probe.unlink()

        # Backpressure: oldest dropped first, and the drop is COUNTED.
        for name in ["20260901T100000Z-7b2e9f04-0001.jsonl.gz",
                     "20260901T110000Z-7b2e9f04-0002.jsonl.gz",
                     "20260901T120000Z-7b2e9f04-0003.jsonl.gz"]:
            (paths["spool"] / name).write_bytes(b"x" * 1000)
        # A name that does not match the contract is IGNORED, never uploaded -
        # we cannot derive a key for it, and guessing is worse than skipping.
        # (A run_id is hex, so "-run-" is genuinely unparseable, not a typo.)
        (paths["spool"] / "stray.jsonl.gz").write_bytes(b"y" * 1000)
        (paths["spool"] / "20260901T130000Z-run-0004.jsonl.gz").write_bytes(b"z" * 1000)
        assert len(spool_files(paths["spool"])) == 3, spool_files(paths["spool"])

        dropped = enforce_ceiling(paths, ceiling=4500)
        assert dropped == 1, dropped
        remaining = [f.name for f in spool_files(paths["spool"])]
        assert remaining == ["20260901T110000Z-7b2e9f04-0002.jsonl.gz",
                             "20260901T120000Z-7b2e9f04-0003.jsonl.gz"], remaining
        drops = json.loads((paths["state"] / "drops.json").read_text())
        assert drops["dropped_files"] == 1 and drops["dropped_bytes"] == 1000, drops

        # Under the ceiling, nothing is dropped.
        assert enforce_ceiling(paths, ceiling=10 ** 9) == 0

        print("sync_task self-test: PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        _selftest()
        return
    run_once()


if __name__ == "__main__":
    main()
