# =============================================================
# FILE: src/normalizer/schema.py
# VERSION: 2.0.0
# UPDATED: 2026-04-26
# PURPOSE: Defines the flat universal event schema.
#          Every field documented. Every field always present.
#          No nested paths. No OCSF knowledge required by consumers.
#          LogAnalyzer, Grafana, Splunk, Streamlit all read this directly.
# OWNER: Ravi Venugopal, Giggso Inc
# AUDIT LOG:
#   v1.0.0  2026-04-18  Initial.
#   v2.0.0  2026-04-26  Phase 1A — added 12 optional fields covering
#                       MCP servers, agent workflows / scheduled, tool
#                       registrations, vector DBs, repo + scan metadata.
#                       Backward-compatible: every new field has a default
#                       so legacy events still serialize cleanly.
#   v2.1.0  2026-09-04  Scanner-graft Phase 3 — added 23 optional fields
#                       for declared_dependency, browser_extension, and
#                       hardcoded_secret findings. Same backward-
#                       compatible-default rule as v2.0.0.
# =============================================================

import uuid
from datetime import datetime, timezone

SCANNER_VERSION = "2.0.0"

# Flat universal schema — canonical field list
FLAT_SCHEMA = {
    "event_id":        "",   # unique UUID per event
    "timestamp":       "",   # ISO 8601 UTC
    "class_uid":       4001, # OCSF Network Activity — audit trail only
    "source":          "",   # packetbeat | vpc_flow | zeek | nac_csv
    "src_ip":          "",   # source IP address
    "src_mac":         "",   # source MAC address
    "src_hostname":    "",   # source hostname
    "dst_domain":      "",   # destination domain — primary match field
    "dst_ip":          "",   # destination IP
    "dst_port":        0,    # destination port
    "protocol":        "",   # TCP | UDP | ICMP
    "bytes_out":       0,    # bytes sent to destination
    "process_name":    "",   # process making the call (Packetbeat only)
    "root_pid":            0,   # root-process dedup: PID chosen to represent a multi-process app
    "root_process_name":   "",  # command line of that root PID
    "instance_process_count": 0,  # real OS process count collapsed into this one finding
    "start_timestamp":     "",  # root process creation time (ISO 8601, UTC)
    "session_duration_seconds": 0,  # now - start_timestamp; 0 if the OS couldn't provide one
    "platform":            "",  # meeting-bot vendor (fathom | otter)
    "join_timestamp":      "",  # meeting_bot only - process-start proxy, NOT a true meeting-join time
    "calls_per_10_min":    0,   # observed_network_target - real connections/10min for this DOMAIN (not per-process)
    "high_frequency_flag": False,  # observed_network_target - calls_per_10_min >= the team's own threshold
    "owner":           "",   # resolved employee identity
    "department":      "",   # resolved department
    "mac_address":     "",   # device MAC
    "geo_country":     "",   # destination country
    "asset_type":      "",   # laptop | ec2 | ecs | eks | unknown
    "cloud_provider":  "",   # aws | gcp | azure | on-prem
    "company":         "",   # company slug
    "scanner_version": SCANNER_VERSION,
    # Filled by matcher.py after normalisation
    "provider":        "",   # matched AI provider name
    "category":        "",   # matched category from unauthorized.csv
    "severity":        "",   # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    "outcome":         "",   # AUTHORIZED | UNAUTHORIZED | GREYLIST | UNKNOWN
    # Marauder Scan — code signal fields (empty for network events)
    "code_snippet":    "",   # first 80 lines of triggering file
    "file_path":       "",   # path of triggering file on device
    "git_diff":        "",   # staged diff snippet from pre-commit hook
    "repo":            "",   # git repo name
    "branch":          "",   # git branch name
    # Phase 1A — MCP server inventory (mcp_server findings only)
    "mcp_host":        "",   # claude_desktop | claude_code | cursor | continue | cline
    "config_sha256":   "",   # SHA-256 of the parent MCP config file
    "server_name":     "",   # server label as defined in mcpServers
    "command_basename": "",  # leaf executable name (no path); empty for remote servers
    "arg_flags":       [],   # flag-shaped args only, values dropped
    "env_keys_present": [],  # env var KEYS only, values dropped
    "transport":       "",   # stdio | http | sse
    "mcp_server_url":  "",   # remote server URL; empty for stdio-type servers
    "process_running": False,  # stdio-type server's command found in the real process table
    "listening_port":  0,    # vector_db (source=listening_port) - real bound TCP port
    "container_id":    "",   # vector_db - Docker container ID if containerized, else ""
    "container_image": "",   # vector_db - Docker image name if containerized, else ""
    "domain":           "",  # observed_network_target - real TLS SNI hostname
    "observation_count": 0,  # observed_network_target - real TLS handshakes seen this window
    "first_seen":       "",  # observed_network_target - ISO 8601, first handshake this window
    "last_seen":        "",  # observed_network_target - ISO 8601, most recent handshake this window
    # Phase 1A — agent workflow / scheduled / tools / vector DB
    "framework":       "",   # n8n | flowise | langflow | crewai | autogen | …
    "schedule_expr":   "",   # cron string when trigger=crontab
    "kind":            "",   # vector DB kind: chroma | faiss | lancedb | …
    "scan_kind":       "",   # baseline | recurring (set by agent footer)
    "scan_id":         "",   # groups every event from one scan together
    # Scanner-graft — declared_dependency findings (AI-SDK-Scanner adapter)
    "repo_safe":            "",    # redacted repo path (~/... form) the finding came from
    "dependency_name":      "",    # raw package/library name as declared
    "dependency_version":   "",    # raw declared version string
    "normalized_name":      "",    # dependency_name normalised for cross-ecosystem matching
    "ecosystem":            "",    # python | node | java_maven | java_gradle | go | rust | dotnet | ruby | php
    "is_ai_related":        False, # matched the AI/ML catalog
    "is_direct":            False, # direct dependency vs transitive (lockfile-resolved)
    "manifest_kind":        "",    # requirements.txt | pyproject.toml | package.json | …
    "line_number":          None,  # line in the source manifest/file the finding was on
    # Scanner-graft — browser_extension findings (Extension Searcher adapter)
    "extension_id":         "",    # store/profile extension id
    "name":                 "",    # generic display name — also used by vector_db, unclassified_software
    "version":              "",    # extension version string
    "browser":              "",    # Google Chrome | Mozilla Firefox | Safari | …
    "browser_profile":      "",    # profile name within the browser
    "enabled":              False, # extension enabled state
    "install_origin":       "",    # web_store | sideloaded | policy | unknown
    "host_permissions":     [],    # requested host match patterns
    "permissions":          [],    # requested extension permissions
    "high_privilege_host_access": False,  # near-total host access (<all_urls> etc.)
    # Scanner-graft — hardcoded_secret findings (apikey-scanner adapter)
    "secret_pattern":       "",    # matched pattern type, e.g. aws_access_key_id — never the secret itself
    "confidence":           "",    # apikey-scanner's own confidence tier for the match
    "blame_commit":         "",    # git blame commit sha for the matched line
    "blame_author":         "",    # git blame author name for the matched line
    "provenance_state":     "",    # committed | uncommitted_change | not_a_repo | unknown
}


def empty_event(source: str, company: str = "") -> dict:
    """Return a fresh copy of the flat schema with defaults stamped."""
    event = dict(FLAT_SCHEMA)
    event["event_id"]  = str(uuid.uuid4())
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    event["source"]    = source
    event["company"]   = company
    return event


def protocol_number(proto: str) -> str:
    """Convert VPC Flow Log protocol number to name."""
    return {"6": "TCP", "17": "UDP", "1": "ICMP", "-": "UNKNOWN"}.get(
        proto, proto.upper()
    )


def infer_asset_type(ip: str) -> str:
    """Rough heuristic — RFC1918 = laptop/on-prem, else EC2."""
    if any(ip.startswith(p) for p in ("10.", "172.16.", "192.168.")):
        return "laptop"
    return "ec2"
