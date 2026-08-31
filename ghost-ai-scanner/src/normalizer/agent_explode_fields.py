# =============================================================
# FILE: src/normalizer/agent_explode_fields.py
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-04-26
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Per-category whitelist of Phase 1A finding-fields that get
#          copied onto the flat event as top-level columns. Lets the
#          dashboard render without parsing the `notes` JSON blob.
#          Anything not on this list still survives in `notes` for
#          audit replay. Extracted from agent_explode.py to honour the
#          150-LOC cap when Phase 1A categories landed.
# DEPENDS: stdlib only
# AUDIT LOG:
#   v1.0.0  2026-04-26  Initial. Phase 1A. Split out of agent_explode.py.
#   v1.1.0  2026-08-31  Add "process" (legacy category, by exception) so
#                       root-process dedup fields (root_pid,
#                       instance_process_count) are dashboard-visible
#                       instead of only living in the notes blob.
#   v1.2.0  2026-08-31  Add start_timestamp / session_duration_seconds
#                       to "process" (Autonomous AI Agents D4b1/D4b2).
#   v1.3.0  2026-08-31  Add "meeting_bot" (Virtual Meeting Bots D4c1/D4c2).
#   v1.4.0  2026-08-31  Add process_running to "mcp_server" - config/
#                       process correlation for stdio-type servers.
#   v1.5.0  2026-08-31  Add listening_port/container_id/container_image
#                       to "vector_db" (D2c1/D2c2 process/port detection,
#                       additive alongside the file-signature scanner).
# =============================================================

# Field whitelist per Phase 1A finding category. Anything outside this
# table is intentionally left in `notes` and not promoted to a column.
PHASE_1A_FIELD_MAP = {
    "process":           ("root_pid", "root_process_name", "instance_process_count",
                          "start_timestamp", "session_duration_seconds"),
    "mcp_server":        ("mcp_host", "config_sha256", "config_basename",
                          "server_name", "command_basename", "arg_flags",
                          "env_keys_present", "transport", "mcp_server_url",
                          "process_running"),
    "agent_workflow":    ("framework", "filename", "file_safe",
                          "bytes", "mtime_epoch"),
    "agent_scheduled":   ("trigger", "schedule_expr", "command_safe",
                          "plist_name", "plist_safe"),
    "tool_registration": ("repo_name", "repo_safe", "remote_host", "head_sha",
                          "total_tools", "files_with_tools", "per_file"),
    "vector_db":         ("kind", "source", "path_safe", "name",
                          "bytes", "mtime_epoch", "repo_name",
                          "listening_port", "container_id", "container_image"),
    "meeting_bot":       ("platform", "root_pid", "instance_process_count", "join_timestamp"),
}


def copy_phase_1a_fields(event: dict, finding: dict) -> None:
    """Copy whitelisted fields from `finding` into `event` for Phase 1A
    categories. No-op for legacy categories (their fields already land
    via process_name / dst_domain). Pure dict mutation; no return."""
    fields = PHASE_1A_FIELD_MAP.get(finding.get("type", ""))
    if not fields:
        return
    for k in fields:
        if k in finding:
            event[k] = finding[k]
