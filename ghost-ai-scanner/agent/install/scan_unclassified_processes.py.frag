# =============================================================
# FRAGMENT: scan_unclassified_processes.py.frag
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Broad process visibility beyond the known-AI catalog. Catalog
#          matching (scan_processes.py.frag, scan_meeting_bots.py.frag)
#          can only ever catch tools we already know the name of - a
#          genuinely new or obscure AI tool sails through untouched.
#          This fragment closes that gap: every real running process
#          that ISN'T already AI-matched, ISN'T an OS-shipped system
#          process, and ISN'T on the org's authorized list becomes a
#          LOW-severity "unclassified_software" finding - visible for
#          periodic review, not an alarm. Deliberately reuses
#          _process_records()/_AI_PROCS_RE/_MEETING_BOT_RE/_is_authorized
#          from the earlier fragments (shared execution namespace, same
#          pattern as every other fragment in this pipeline) rather than
#          duplicating them, so this stays in sync automatically if
#          those ever change.
#          Tiered severity is the point: a real new risk still stands
#          out as HIGH/MEDIUM in its own category once someone reviews
#          an unclassified entry and it gets catalogued - it doesn't get
#          buried in a flood of every process on the machine, and
#          Notepad/Excel/Slack don't get invented severity ratings they
#          don't need.
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial.
# =============================================================

_KNOWN_OS_PROCESSES = {
    # Windows
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe", "explorer.exe", "dwm.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe", "searchapp.exe",
    "spoolsv.exe", "conhost.exe", "sihost.exe", "fontdrvhost.exe", "ctfmon.exe",
    "dllhost.exe", "logonui.exe", "wmiprvse.exe", "backgroundtaskhost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "securityhealthsystray.exe", "securityhealthservice.exe", "audiodg.exe",
    "msmpeng.exe", "nissrv.exe", "smartscreen.exe", "textinputhost.exe",
    "applicationframehost.exe", "systemsettings.exe", "usoclient.exe",
    "trustedinstaller.exe", "memcompression",
    # macOS
    "launchd", "kernel_task", "windowserver", "loginwindow", "finder", "dock",
    "systemuiserver", "coreaudiod", "mds", "mdworker", "cfprefsd", "distnoted",
    "usereventagent", "syslogd", "sharingd", "cloudd", "backupd", "spotlight",
    "notifyd", "coreservicesd", "diskarbitrationd", "powerd", "logd",
    # Linux
    "systemd", "init", "kthreadd", "dbus-daemon", "networkmanager", "sshd",
    "cron", "rsyslogd", "udevd", "polkitd", "gdm", "gdm3", "xorg", "x11",
    "pulseaudio", "pipewire", "snapd", "accounts-daemon", "upowerd",
}

_UNCLASSIFIED_MAX_FINDINGS = 50


def _is_known_os_process(name: str) -> bool:
    n = name.lower()
    if n in _KNOWN_OS_PROCESSES:
        return True
    return n.startswith("kworker")  # Linux kernel worker threads: kworker/0:1, kworker/u8:2, ...


def _is_already_ai_matched(cmd_col: str) -> bool:
    """True if a dedicated AI-category fragment already caught this
    process - avoids double-counting the same real process under both
    its specific category and the generic unclassified bucket."""
    if "_AI_PROCS_RE" in globals() and _AI_PROCS_RE.search(cmd_col):
        return True
    if "_MEETING_BOT_RE" in globals() and _MEETING_BOT_RE.search(cmd_col):
        return True
    return False


def scan_unclassified_processes() -> list:
    """Every real running process that isn't a known OS process, isn't
    already caught by an AI-specific category, and isn't on the org's
    authorized list. LOW severity, root-process deduped per name -
    visible for review, not an alarm. Catches genuinely new/unknown
    tools no catalog has a name for yet."""
    families: dict = {}
    for pid, cmd_col in _process_records():
        base = cmd_col.strip()
        if not base or _is_known_os_process(base) or _is_already_ai_matched(base):
            continue
        if _is_authorized(base.lower()):
            continue
        fam = families.setdefault(base.lower(), {"root_pid": pid, "root_name": base, "count": 0})
        fam["count"] += 1
        if pid < fam["root_pid"]:
            fam["root_pid"], fam["root_name"] = pid, base

    findings: list = []
    for _, fam in families.items():
        findings.append({
            "type":                    "unclassified_software",
            "name":                    fam["root_name"][:200],
            "root_pid":                fam["root_pid"],
            "instance_process_count":  fam["count"],
        })
        if len(findings) >= _UNCLASSIFIED_MAX_FINDINGS:
            break
    return findings
