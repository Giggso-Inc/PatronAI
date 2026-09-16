# =============================================================
# FILE: src/normalizer/agent_explode.py
# PROJECT: PatronAI
# VERSION: 1.1.0
# UPDATED: 2026-04-26
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Turn one ENDPOINT_SCAN payload into N flat events — one per
#          finding. The pipeline writes each to the findings store so
#          the inventory dashboard shows them as proper rows.
#          Clean scans (no findings) return [] — heartbeat covers liveness;
#          we don't bloat storage with "scan ran fine" rows.
# DEPENDS: normalizer.schema, normalizer.agent (for _bind_identity)
# AUDIT LOG:
#   v1.0.0  2026-04-26  Initial. Step 0.5 — make endpoint findings visible.
#   v1.1.0  2026-04-26  Phase 1A. Added 4 new finding categories
#                       (mcp_server, agent_workflow, agent_scheduled,
#                       tool_registration, vector_db) to _FINDING_SEVERITY
#                       and _provider_for(). Identity bundle untouched.
#   v1.2.0  2026-09-04  Scanner-graft Phase 3. Added declared_dependency,
#                       browser_extension, hardcoded_secret to
#                       _FINDING_SEVERITY, _provider_for() and
#                       _name_field(). Two of the three have no natural
#                       "name" field, so _provider_for()'s composite key
#                       (not process_name) is what actually guarantees
#                       _finding_signature() uniqueness for them — see
#                       that function's own inline note.
# =============================================================

import hashlib
import json
import logging

from .schema import empty_event

log = logging.getLogger("marauder-scan.normalizer.agent_explode")


def _finding_signature(event: dict) -> str:
    """Stable hash for entity-level dedup across re-emissions.

    Two findings with the same signature represent the SAME real-world
    fact — e.g. "Cursor is running on this MacBook" — even when the
    agent re-emits the scan every 30 min. The findings_compact background
    job (src/jobs/findings_compact.py) merges them into a single row with
    first_seen / last_seen / occurrences, so the dashboard shows 1 finding
    not 21.

    Key dimensions: device + provider + category + the distinctive name
    field (process_name OR dst_domain depending on category).
    """
    key = "|".join([
        event.get("device_uuid") or event.get("device_id") or "",
        event.get("provider", ""),
        event.get("category", ""),
        event.get("process_name") or event.get("dst_domain") or "",
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]

# Severity tier per finding type. Drives alerter routing — HIGH+ goes to
# SNS / Trinity / SES; MEDIUM/LOW land on dashboard only.
_FINDING_SEVERITY = {
    # legacy categories
    "browser":              "HIGH",      # active visit to AI service
    "process":              "HIGH",      # AI tool actively running
    "container_log_signal": "HIGH",      # AI traffic/keys observed in container
    "package":              "MEDIUM",    # installed but maybe unused
    "ide_plugin":           "MEDIUM",    # installed but maybe unused
    "container_image":      "MEDIUM",    # image pulled, may not be running
    "shell_history":        "LOW",       # past command, may be ephemeral
    # Phase 1A additions
    "mcp_server":           "HIGH",      # shell-level access via MCP transport
    "agent_workflow":       "HIGH",      # autonomous loop configured to run
    "agent_scheduled":      "HIGH",      # cron / launchd-triggered AI agent
    "tool_registration":    "MEDIUM",    # @tool decorators in code (capability)
    "vector_db":            "MEDIUM",    # local RAG store; data exposure risk
    "meeting_bot":          "HIGH",      # AI notetaker actively running in a meeting
    "observed_network_target": "MEDIUM",  # real TLS SNI capture; not yet linked to a process
    "unclassified_software": "LOW",      # broad process visibility, tiered deliberately below
                                          # the known-AI categories - a real new risk still
                                          # stands out once catalogued, this doesn't drown it out
    # Scanner-graft additions
    "hardcoded_secret":     "CRITICAL",  # live-looking credential committed to a repo
    "browser_extension":    "MEDIUM",    # raised to HIGH by _adjust_severity() below
    "declared_dependency":  "LOW",       # raised to MEDIUM by _adjust_severity() below
}


def _adjust_severity(ftype: str, finding: dict, base: str) -> str:
    """Per-finding severity escalation for the two scanner-graft types
    whose base tier depends on the finding's own content, not just its
    type. Every other category's severity is the static table lookup —
    this only ever raises, never lowers, `base`."""
    if ftype == "browser_extension" and finding.get("high_privilege_host_access"):
        return "HIGH"
    if ftype == "declared_dependency" and finding.get("is_ai_related"):
        return "MEDIUM"
    return base


def _scan_id(raw: dict) -> str:
    """Stable ID grouping every finding from the same scan back to its origin."""
    return f"{raw.get('token','')}-{raw.get('timestamp','')}"


def _provider_for(finding: dict) -> str:
    """Pick a human-readable provider label per finding for dedup keying."""
    ftype = finding.get("type", "")
    # Legacy categories
    if ftype == "browser":
        return finding.get("domain", "browser")
    if ftype == "package":
        return f"{finding.get('manager','pkg')}:{finding.get('name','')}"
    if ftype == "process":
        return finding.get("name", "process")
    if ftype == "ide_plugin":
        return finding.get("plugin_id", "ide_plugin")
    if ftype == "container_image":
        return finding.get("image", "container_image")
    if ftype == "container_log_signal":
        return f"container:{finding.get('signal','log')}"
    if ftype == "shell_history":
        return f"shell:{(finding.get('command_hint','') or 'cmd')[:40]}"
    # Phase 1A categories
    if ftype == "mcp_server":
        return f"mcp:{finding.get('mcp_host','')}:{finding.get('server_name','')}"
    if ftype == "agent_workflow":
        return f"workflow:{finding.get('framework','')}:{finding.get('filename','')}"
    if ftype == "agent_scheduled":
        return f"sched:{finding.get('trigger','')}:{(finding.get('command_safe','') or finding.get('plist_name',''))[:40]}"
    if ftype == "tool_registration":
        return f"tools:{finding.get('repo_name','')}"
    if ftype == "vector_db":
        return f"vdb:{finding.get('kind','')}:{finding.get('name') or finding.get('listening_port','')}"
    if ftype == "meeting_bot":
        return f"meeting:{finding.get('platform','')}"
    if ftype == "observed_network_target":
        return f"net:{finding.get('domain','')}"
    if ftype == "unclassified_software":
        return f"unclassified:{finding.get('name','')}"
    if ftype == "declared_dependency":
        return f"dep:{finding.get('ecosystem','')}:{finding.get('dependency_name','')}:{finding.get('repo_safe','')}"
    if ftype == "browser_extension":
        return f"ext:{finding.get('browser','')}:{finding.get('extension_id','')}"
    if ftype == "hardcoded_secret":
        return (f"secret:{finding.get('provider','')}:{finding.get('repo_safe','')}:"
                f"{finding.get('file_path','')}:{finding.get('line_number','')}")
    return ftype or "unknown"


def _name_field(f: dict) -> str:
    """Distinctive identifier for non-browser findings → goes into process_name.
    Note: declared_dependency and hardcoded_secret have no single field
    that's unique on its own here (dependency_name repeats across repos;
    secret_pattern repeats across findings) — true uniqueness for both
    comes from _provider_for()'s composite key, not this one."""
    return (f.get("name") or f.get("platform") or f.get("plugin_id") or f.get("image")
            or f.get("signal") or f.get("kind") or f.get("domain")
            or f.get("dependency_name") or f.get("secret_pattern")
            or (f.get("command_hint", "") or "")[:140])


# Phase 1A field-copy logic split into agent_explode_fields.py to keep
# this file under the 150-LOC cap. See that module's docstring.
from .agent_explode_fields import copy_phase_1a_fields as _copy_phase_1a_fields


def explode_endpoint_findings(raw: dict, company: str, bind_identity) -> list:
    """
    Turn one ENDPOINT_SCAN payload into one flat event per finding.
    `bind_identity(event, raw)` is passed in to avoid a circular import
    with normalizer/agent.py.
    Returns [] for clean scans — pipeline drops the whole payload.
    """
    findings = raw.get("findings") or []
    if not findings:
        return []
    events: list = []
    sid = _scan_id(raw)
    for f in findings:
        ftype = f.get("type", "")
        event = empty_event("agent_endpoint_scan", company)
        bind_identity(event, raw)
        event["timestamp"] = raw.get("timestamp", event["timestamp"])
        event["outcome"]   = "ENDPOINT_FINDING"
        event["severity"]  = _adjust_severity(ftype, f, _FINDING_SEVERITY.get(ftype, "LOW"))
        event["provider"]  = _provider_for(f)
        event["category"]  = ftype
        event["scan_id"]   = sid
        if ftype == "browser":
            event["dst_domain"]   = f.get("domain", "")
        else:
            event["process_name"] = _name_field(f)
        # Copy Phase 1A fields onto the event so dashboards render them
        # without parsing the `notes` blob. No-op for legacy categories.
        _copy_phase_1a_fields(event, f)
        # Pass through scan_kind so dashboard can split baseline vs recurring.
        event["scan_kind"] = raw.get("scan_kind", "recurring")
        # Stable signature for entity-level dedup. Same Cursor process
        # on the same device produces the same signature every cycle —
        # findings_compact uses it to collapse 21 hourly rows into 1.
        event["finding_signature"] = _finding_signature(event)
        event["notes"] = json.dumps({
            "scan_id": sid, "finding": f, "token": raw.get("token", ""),
        })
        events.append(event)
    log.debug(f"ENDPOINT_SCAN exploded into {len(events)} events "
              f"from {raw.get('device_id','?')}")
    return events
