# =============================================================
# FRAGMENT: scan_processes.py.frag
# VERSION: 1.0.0
# UPDATED: 2026-04-25
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Enumerate currently running AI-tool processes via ps.
#          Filtered through AUTH_LIST. Returns finding dicts.
# AUDIT LOG:
#   v1.0.0  2026-04-25  Initial. Extracted from setup_agent.sh.template.
#   v1.1.0  2026-08-28  Add claude, power automate desktop, fathom, otter —
#                       confirmed 0/31 real-process detection rate before this fix.
#   v1.2.0  2026-08-31  Root-process dedup: multi-process apps (Fathom real
#                       count 5, Otter real count 11 - confirmed against
#                       real running instances) now collapse to one finding
#                       per matched app family instead of one per process,
#                       keyed on the lowest real PID in that family.
# =============================================================

_AI_PROCS_RE = re.compile(
    r"\b(n8n|ollama|lm[._-]studio|lmstudio|gpt4all|jan|cursor|copilot|"
    r"codeium|tabnine|msty|chatbox|typing-mind|flowise|langflow|"
    r"claude|pad\.console\.host|pad\.automationserver|fathom|otter)\b",
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


def scan_processes() -> list:
    """OS-aware process enumeration → regex match against AI process names.
    One finding per matched keyword family (root-process dedup): the
    family's root is its lowest real PID, with instance_process_count
    showing how many real OS processes back that one finding."""
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
    for keyword, fam in families.items():
        findings.append({
            "type":                    "process",
            "name":                    keyword,
            "root_pid":                fam["root_pid"],
            "root_process_name":       fam["root_name"][:200],
            "instance_process_count":  fam["count"],
        })
    return findings
