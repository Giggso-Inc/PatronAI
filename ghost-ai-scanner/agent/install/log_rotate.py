#!/usr/bin/env python3
# =============================================================
# PatronAI -- Agent log rotation (cross-platform, stdlib only)
# PURPOSE : Drop heartbeat entries older than 24 h from agent.log.
#           All other entry types (scan, update_failed, etc.) are
#           kept indefinitely.
# SCHEDULE: Every 30 min, alongside the scan job.
# =============================================================
from __future__ import annotations

import datetime
import json
import os
import sys
import time
from pathlib import Path

AGENT_DIR     = Path.home() / ".patronai"
LOG_PATH      = AGENT_DIR / "agent.log"
HEARTBEAT_TTL = 24 * 3600   # seconds -- entries older than this are dropped


def _keep(line: str, now: float) -> bool:
    line = line.strip()
    if not line:
        return False
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return True  # keep unparseable lines untouched

    if entry.get("type") != "heartbeat":
        return True  # scans and all other types: always keep

    ts_str = entry.get("ts", "")
    if not ts_str:
        return True  # no timestamp -- keep to be safe
    try:
        ts_clean = ts_str.rstrip("Z").replace("T", " ")
        dt = datetime.datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
        entry_epoch = dt.replace(tzinfo=datetime.timezone.utc).timestamp()
    except Exception:
        return True  # unparseable timestamp -- keep

    return (now - entry_epoch) < HEARTBEAT_TTL


def rotate() -> None:
    if not LOG_PATH.exists():
        return

    now = time.time()
    original = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    kept = [ln for ln in original if _keep(ln, now)]

    dropped = len(original) - len(kept)
    if dropped == 0:
        return  # nothing to do -- skip the write entirely

    tmp = LOG_PATH.with_suffix(".log.tmp")
    try:
        tmp.write_text(
            "\n".join(kept) + ("\n" if kept else ""),
            encoding="utf-8",
        )
        os.replace(tmp, LOG_PATH)  # atomic on POSIX and Windows
    except Exception as exc:
        print(f"[patronai] log_rotate: write failed: {exc}", file=sys.stderr)
        tmp.unlink(missing_ok=True)
        sys.exit(1)

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[patronai] log_rotate: {ts} -- dropped {dropped} heartbeat line(s) "
          f"older than 24 h ({len(kept)} line(s) remaining).")


if __name__ == "__main__":
    rotate()
