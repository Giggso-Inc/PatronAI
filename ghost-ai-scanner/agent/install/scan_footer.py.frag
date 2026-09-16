# =============================================================
# FRAGMENT: scan_footer.py.frag
# VERSION: 2.0.0
# UPDATED: 2026-04-26
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Bottom of the rendered scan.sh Python block.
#          Calls every scan_*() function defined by sibling fragments,
#          aggregates findings into a single ENDPOINT_SCAN payload,
#          and prints the JSON to stdout. The bash wrapper PUTs it to S3.
# AUDIT LOG:
#   v1.0.0  2026-04-25  Initial. Group 2 — fragment refactor.
#   v2.0.0  2026-04-26  Phase 1A. Four new emitters + scan_kind tag.
#   v2.1.0  2026-05-11  Add snapshot_hash — SHA-256 over the canonical
#                       findings list. Server uses it for cheap "same
#                       state as last cycle" detection (short-circuits
#                       redundant explode + write). Companion to the
#                       server-side findings_compact job. Enables future
#                       v3 agent delta-emission (send hash only, omit
#                       findings array if hash matches the previous send).
#   v2.2.0  2026-08-31  Add scan_meeting_bots() (D4c1/D4c2 - Virtual
#                       Meeting Bots, split out of the generic process
#                       emitter so Fathom/Otter get the category-correct
#                       finding type instead of double-counting).
#   v2.3.0  2026-08-31  Add scan_vector_db_ports() (D2c1/D2c2 - real
#                       listening-port + Docker container_id detection,
#                       additive alongside the file-signature scanner
#                       per team decision - both run, neither replaces
#                       the other).
#   v2.4.0  2026-08-31  Add scan_network_capture() (D2a2 -
#                       observed_network_target, reads Packetbeat's real
#                       NDJSON capture when the optional module is
#                       installed; [] otherwise).
#   v2.5.0  2026-08-31  Add scan_unclassified_processes() - broad process
#                       visibility beyond the known-AI catalog, LOW
#                       severity, tiered separately from the specific
#                       AI-category findings so it doesn't drown them out.
#   v2.6.0  2026-09-04  Scanner-graft adapters (declared_deps,
#                       browser_extensions, hardcoded_secrets) -
#                       no-op ([]) when their companion isn't installed,
#                       same optional-module contract as
#                       scan_network_capture().
# =============================================================

_findings: list = []
# --- legacy emitters ---
_findings += scan_packages()
_findings += scan_processes()
_findings += scan_browsers()
_findings += scan_ide_plugins()
_findings += scan_containers()
_findings += scan_shell_history()
# --- Phase 1A new emitters ---
_findings += scan_mcp_configs()
_findings += scan_agents_workflows()
_findings += scan_tools_code()
_findings += scan_vector_dbs()
_findings += scan_vector_db_ports()
_findings += scan_meeting_bots()
_findings += scan_network_capture()
_findings += scan_unclassified_processes()
# --- scanner-graft companion adapters ---
_findings += scan_declared_deps()
_findings += scan_browser_extensions()
_findings += scan_hardcoded_secrets()


def _count(kind: str) -> int:
    """Count findings of a given type for the summary block."""
    return sum(1 for f in _findings if f.get("type") == kind)


_scan_kind = "baseline" if IS_FIRST_RUN else "recurring"


def _snapshot_hash(findings_list):
    """SHA-256 over the canonical sort of (type, key) tuples per finding.
    Server short-circuits when this matches the previous scan's hash —
    no explode, no findings_store write, no false-noise alerts."""
    import hashlib
    keys = []
    for _f in findings_list:
        _t = _f.get("type", "")
        # Pick the most stable distinguishing field per category. The
        # file_path+line_number fallback is scoped to hardcoded_secret
        # only, so it can't shadow declared_dependency's own file_path.
        _k = (_f.get("domain") or _f.get("name") or _f.get("plugin_id")
              or _f.get("image") or _f.get("server_name")
              or _f.get("filename") or _f.get("signal")
              or _f.get("dependency_name")
              or (f"{_f.get('file_path','')}:{_f.get('line_number','')}"
                  if _t == "hardcoded_secret" else "")
              or "")
        keys.append(f"{_t}|{_k}")
    keys.sort()
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()[:16]


_payload = {
    "event_type":   "ENDPOINT_SCAN",
    "source":       "patronai_scan_agent",
    "device_id":    DEVICE_ID,
    "device_uuid":  DEVICE_UUID,
    "mac_primary":  MAC_PRIMARY,
    "ip_set":       IP_SET,
    "email":        EMAIL,
    "token":        TOKEN,
    "company":      COMPANY,
    "os_name":      OS_NAME,
    "timestamp":    NOW,
    "scan_kind":    _scan_kind,
    "snapshot_hash": _snapshot_hash(_findings),
    "authorized":   AUTH_LIST,
    "repos_discovered": [{"name": r.get("name"),
                          "remote_host": r.get("remote_host"),
                          "head_sha": r.get("head_sha"),
                          "path_safe": r.get("path_safe")}
                         for r in DISCOVERED_REPOS],
    "findings":     _findings,
    "summary": {
        "packages":              _count("package"),
        "processes":             _count("process"),
        "browser_hits":          _count("browser"),
        "ide_plugins":           _count("ide_plugin"),
        "container_images":      _count("container_image"),
        "container_log_signals": _count("container_log_signal"),
        "shell_history":         _count("shell_history"),
        "mcp_servers":           _count("mcp_server"),
        "agent_workflows":       _count("agent_workflow"),
        "agent_scheduled":       _count("agent_scheduled"),
        "tool_registrations":    _count("tool_registration"),
        "vector_dbs":            _count("vector_db"),
        "meeting_bots":          _count("meeting_bot"),
        "observed_network_targets": _count("observed_network_target"),
        "unclassified_software": _count("unclassified_software"),
        "repos_discovered":      len(DISCOVERED_REPOS),
        "declared_dependencies": _count("declared_dependency"),
        "browser_extensions":    _count("browser_extension"),
        "hardcoded_secrets":     _count("hardcoded_secret"),
    },
}

# Drop the first-run flag now that a complete payload is ready.
# Best-effort — never block a scan on a flag-clearing failure.
try:
    _clear_first_run_flag()
except Exception:
    pass

print(json.dumps(_payload))
