# =============================================================
# FILE: scripts/scan_fragment_loader.py
# VERSION: 2.0.0
# UPDATED: 2026-04-26
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Concatenate scan_*.py.frag fragments into a single Python
#          block that gets inlined into both setup_agent.sh.template
#          and setup_agent.ps1.template via the {{INLINE_SCAN_PYTHON}}
#          placeholder. Order is fixed — header first, footer last.
# DEPENDS: stdlib only
# AUDIT LOG:
#   v1.0.0  2026-04-25  Initial. Group 2 — template fragment refactor.
#   v2.0.0  2026-04-26  Phase 1A. Inserted utility fragments (redactor,
#                       repo_discovery, first_run) BEFORE the legacy
#                       scanners so they expose helpers + globals; added
#                       4 new emitter scanners (mcp_configs, agents_
#                       workflows, tools_code, vector_dbs) BEFORE footer.
#   v2.1.0  2026-09-04  Scanner graft Phase 2. Three companion-package
#                       adapters (declared_deps, browser_extensions,
#                       hardcoded_secrets) appended after the existing
#                       Phase 1A emitters, before the footer — same
#                       ordering constraint as scan_tools_code /
#                       scan_vector_dbs: they consume DISCOVERED_REPOS
#                       and _safe_finding, both set up earlier in the
#                       list.
#   v2.2.0  2026-09-04  Scanner graft Phase 4. Inserted
#                       scan_mcp_configs_extra_hosts.py.frag right
#                       after scan_mcp_configs.py.frag — a companion
#                       file (not a new emitter call in the footer;
#                       scan_mcp_configs() itself calls into it) kept
#                       out of scan_mcp_configs.py.frag to respect its
#                       150-LOC cap.
# =============================================================

from pathlib import Path

# Order matters — header sets globals; utilities expose shared helpers;
# legacy scanners remain unchanged; new emitters call the utilities;
# footer consumes every scan_* function.
FRAGMENT_ORDER = (
    "scan_header.py.frag",
    # --- Phase 1A utility fragments (must precede every emitter that
    #     uses _redact_*, DISCOVERED_REPOS, or IS_FIRST_RUN) ---
    "scan_redactor.py.frag",
    "scan_repo_discovery.py.frag",
    "scan_first_run.py.frag",
    # --- legacy emitters (unchanged) ---
    "scan_packages.py.frag",
    "scan_processes.py.frag",
    "scan_browsers.py.frag",
    "scan_ide_plugins.py.frag",
    "scan_containers.py.frag",
    "scan_shell_history.py.frag",
    # --- Phase 1A new emitters ---
    "scan_mcp_configs.py.frag",
    "scan_mcp_configs_extra_hosts.py.frag",
    "scan_agents_workflows.py.frag",
    "scan_tools_code.py.frag",
    "scan_vector_dbs.py.frag",
    "scan_vector_db_ports.py.frag",
    "scan_meeting_bots.py.frag",
    "scan_network_capture.py.frag",
    # scan_unclassified_processes must come after scan_processes.py.frag
    # and scan_meeting_bots.py.frag - it reuses their _AI_PROCS_RE /
    # _MEETING_BOT_RE globals to avoid double-counting an already
    # AI-matched process under the generic unclassified bucket too.
    "scan_unclassified_processes.py.frag",
    # --- scanner-graft companion adapters (must follow scan_redactor
    #     and scan_repo_discovery above) ---
    "scan_declared_deps.py.frag",
    "scan_browser_extensions.py.frag",
    "scan_hardcoded_secrets.py.frag",
    # --- footer last (aggregates all scan_*) ---
    "scan_footer.py.frag",
)


def load_scan_fragments(fragment_dir: Path) -> str:
    """Concatenate all scan_*.py.frag files in FRAGMENT_ORDER.

    Raises FileNotFoundError if any expected fragment is missing — surfaces
    misconfiguration loudly rather than silently shipping a broken installer.
    """
    parts: list = []
    for name in FRAGMENT_ORDER:
        path = fragment_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Missing scan fragment: {path}")
        parts.append(f"# ── {name} ──\n{path.read_text(encoding='utf-8')}")
    return "\n\n".join(parts)
