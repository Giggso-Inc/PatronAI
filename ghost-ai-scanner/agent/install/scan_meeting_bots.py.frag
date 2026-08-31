# =============================================================
# FRAGMENT: scan_meeting_bots.py.frag
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Virtual Meeting Bots (D4c1/D4c2). Detects real desktop meeting-
#          bot clients (Fathom, Otter) as their own category, distinct
#          from the generic AI-process bucket, with root-process dedup
#          and session duration (same real-tested pattern as
#          scan_processes.py.frag). Previously these matched generically
#          via scan_processes.py.frag; moved here so they get the
#          category-correct type + fields instead of double-counting.
# NOT INCLUDED (investigated for real, not assumed):
#   - bot_account_name / meeting_id: real account/session data for these
#     apps lives in Chromium-style LevelDB (Local/Session Storage), not
#     any plaintext config - confirmed by inspecting Fathom's and
#     Otter's actual AppData on a real machine this session. LevelDB is
#     also typically locked while the app is running. Reading it needs
#     a real parser and a locked-file strategy - a genuinely bigger,
#     separate task, not attempted here rather than faked.
#   - meeting_id via calendar correlation: permanently skipped per an
#     earlier team decision (no calendar account/API access available).
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial.
# =============================================================

_MEETING_BOT_RE = re.compile(r"\b(fathom|otter)\b", re.IGNORECASE)


def _meeting_bot_records() -> list:
    """OS-aware enumeration of (pid, command_line) tuples."""
    if OS_NAME == "windows":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL, text=True, timeout=10,
            )
        except Exception:
            return []
        records: list = []
        for ln in out.splitlines():
            if not ln:
                continue
            parts = [p.strip('"') for p in ln.split(",")]
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            records.append((int(parts[1]), parts[0]))
        return records
    try:
        out = subprocess.check_output(["ps", "aux"], stderr=subprocess.DEVNULL, text=True, timeout=10)
    except Exception:
        return []
    records = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) <= 10 or not parts[1].isdigit():
            continue
        records.append((int(parts[1]), " ".join(parts[10:])))
    return records


def _meeting_bot_start_epoch(pid: int) -> int:
    """Best-effort real start epoch for one PID - same mechanism as
    scan_processes.py.frag (Get-CimInstance on Windows, ps etimes
    elsewhere), scoped to a single lookup since this category only
    ever needs a handful of root PIDs per scan, not the whole table."""
    if OS_NAME == "windows":
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 f"$p = Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\"; "
                 "if ($p) { [int64](($p.CreationDate.ToUniversalTime() - "
                 "(Get-Date '1970-01-01').ToUniversalTime()).TotalSeconds) }"],
                stderr=subprocess.DEVNULL, text=True, timeout=10,
            ).strip()
            return int(out) if out.isdigit() else 0
        except Exception:
            return 0
    try:
        out = subprocess.check_output(
            ["ps", "-o", "etimes=", "-p", str(pid)], stderr=subprocess.DEVNULL, text=True, timeout=10,
        ).strip()
        if out.isdigit():
            return int(datetime.now(timezone.utc).timestamp()) - int(out)
    except Exception:
        pass
    return 0


def scan_meeting_bots() -> list:
    """One finding per matched meeting-bot platform (root-process dedup) -
    real Otter installs run 11 OS processes, Fathom runs 5, both off one
    root (confirmed against real installs this session)."""
    families: dict = {}
    for pid, cmd_col in _meeting_bot_records():
        m = _MEETING_BOT_RE.search(cmd_col)
        if not m:
            continue
        platform_name = m.group(0).lower()
        if _is_authorized(platform_name):
            continue
        fam = families.setdefault(platform_name, {"root_pid": pid, "count": 0})
        fam["count"] += 1
        if pid < fam["root_pid"]:
            fam["root_pid"] = pid

    findings: list = []
    for platform_name, fam in families.items():
        finding = {
            "type":                    "meeting_bot",
            "platform":                platform_name,
            "root_pid":                fam["root_pid"],
            "instance_process_count":  fam["count"],
        }
        start_epoch = _meeting_bot_start_epoch(fam["root_pid"])
        if start_epoch:
            started = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
            finding["join_timestamp"] = started.isoformat()  # proxy: process start, not true meeting-join time
        findings.append(finding)
    return findings
