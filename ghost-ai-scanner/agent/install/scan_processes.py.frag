# =============================================================
# FRAGMENT: scan_processes.py.frag
# VERSION: 1.0.0
# UPDATED: 2026-04-25
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Enumerate currently running AI-tool processes via ps.
#          Filtered through AUTH_LIST. Returns finding dicts.
# AUDIT LOG:
#   v1.0.0  2026-04-25  Initial. Extracted from setup_agent.sh.template.
#   v1.1.0  2026-08-28  Add claude/PAD/fathom/otter - real detection was
#                       0/31 before this fix.
#   v1.2.0  2026-08-31  Root-process dedup: real multi-process apps
#                       (Fathom=5, Otter=11 procs) now collapse to one
#                       finding per app family, keyed on the lowest PID.
#   v1.3.0  2026-08-31  Add start_timestamp / session_duration_seconds
#                       (D4b1/D4b2) via Get-CimInstance (Windows - wmic
#                       returned nothing on a real Win11 24H2+ box this
#                       session) / `ps -eo pid,etimes` (macOS/Linux).
#                       api_call_frequency excluded - needs network
#                       telemetry, not built yet.
#   v1.4.0  2026-08-31  Remove fathom/otter - moved to their own category,
#                       scan_meeting_bots.py.frag (D4c1/D4c2), so the same
#                       app isn't double-counted under two finding types.
# =============================================================

_AI_PROCS_RE = re.compile(
    r"\b(n8n|ollama|lm[._-]studio|lmstudio|gpt4all|jan|cursor|copilot|"
    r"codeium|tabnine|msty|chatbox|typing-mind|flowise|langflow|"
    r"claude|pad\.console\.host|pad\.automationserver)\b",
    re.IGNORECASE,
)


def _process_records() -> list:
    """OS-aware enumeration of (pid, command_line) tuples. PID is needed
    to pick a stable root process per app family - a plain command-line
    scan can't tell 11 Otter processes apart from 1."""
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


def _windows_start_epochs() -> dict:
    """PID → process creation epoch (seconds). Uses Get-CimInstance, not
    wmic (unreliable on current Windows builds - see AUDIT LOG). Output
    is locale-independent "PID,epoch" lines, not a formatted date string."""
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | ForEach-Object { "
             "\"$($_.ProcessId),$([int64](($_.CreationDate.ToUniversalTime() - "
             "(Get-Date '1970-01-01').ToUniversalTime()).TotalSeconds))\" }"],
            stderr=subprocess.DEVNULL, text=True, timeout=15,
        )
    except Exception:
        return {}
    epochs: dict = {}
    for line in out.splitlines():
        parts = line.split(",")
        if len(parts) == 2 and parts[0].isdigit() and parts[1].lstrip("-").isdigit():
            epochs[int(parts[0])] = int(parts[1])
    return epochs


def _unix_start_epochs() -> dict:
    """PID → process start epoch (seconds), macOS/Linux. `etimes` gives
    elapsed seconds directly, sidestepping lstart's locale-dependent
    date-string format."""
    try:
        out = subprocess.check_output(
            ["ps", "-eo", "pid,etimes"], stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
    except Exception:
        return {}
    now = int(datetime.now(timezone.utc).timestamp())
    epochs: dict = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            epochs[int(parts[0])] = now - int(parts[1])
    return epochs


def scan_processes() -> list:
    """OS-aware process enumeration → regex match against AI process names.
    One finding per matched keyword family (root-process dedup): the
    family's root is its lowest real PID, with instance_process_count
    showing how many real OS processes back that one finding. Each
    finding also carries the root process's real start_timestamp and
    session_duration_seconds where the OS could provide one."""
    families: dict = {}
    for pid, cmd_col in _process_records():
        m = _AI_PROCS_RE.search(cmd_col)
        if not m:
            continue
        keyword = m.group(0).lower()
        if _is_authorized(keyword):
            continue
        fam = families.setdefault(keyword, {"root_pid": pid, "root_name": cmd_col, "count": 0})
        fam["count"] += 1
        if pid < fam["root_pid"]:
            fam["root_pid"], fam["root_name"] = pid, cmd_col

    findings: list = []
    if families:
        start_epochs = _windows_start_epochs() if OS_NAME == "windows" else _unix_start_epochs()
        now = datetime.now(timezone.utc)
        for keyword, fam in families.items():
            start_epoch = start_epochs.get(fam["root_pid"])
            finding = {
                "type":                    "process",
                "name":                    keyword,
                "root_pid":                fam["root_pid"],
                "root_process_name":       fam["root_name"][:200],
                "instance_process_count":  fam["count"],
            }
            if start_epoch is not None:
                started = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
                finding["start_timestamp"]           = started.isoformat()
                finding["session_duration_seconds"]  = int((now - started).total_seconds())
            findings.append(finding)
    return findings
