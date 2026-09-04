# =============================================================
# FRAGMENT: scan_mcp_configs_extra_hosts.py.frag
# PROJECT: PatronAI — scanner graft, Phase 4
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Companion to scan_mcp_configs.py.frag (already at the
#          150-LOC cap) — 5 more MCP sources, same `mcp_server` shape:
#          vscode_user (settings.json, nested "mcp":{"servers":{}} —
#          the one dialect differing from flat mcpServers),
#          vscode_project (<repo>/.vscode/mcp.json, root "servers",
#          walks DISCOVERED_REPOS not $HOME), windsurf, zed (root
#          "context_servers"), lmstudio, generic (XDG ~/.config/mcp.json).
#          NOT ported: Continue/Goose (YAML config — this agent is
#          stdlib-only, no YAML dep for two clients); MCP Searcher's
#          declared-vs-running "running_undeclared" ghost-server
#          correlation (needs psutil ancestry-first process-tree
#          walking specifically to avoid false positives a flat
#          cmdline match produces — real future work, not a quick add).
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial. Phase 4 of the scanner-graft plan.
# =============================================================

def _mcp_extra_single_paths() -> list:
    """(host_label, path) per single-$HOME-path source. Servers-dict key
    is host-specific — see _servers_from_document."""
    h = Path.home()
    if OS_NAME == "windows":
        appdata = Path(os.environ.get("APPDATA", h / "AppData/Roaming"))
        vscode_user = appdata / "Code/User/settings.json"
        zed = appdata / "Zed/settings.json"
    elif OS_NAME == "darwin":
        vscode_user = h / "Library/Application Support/Code/User/settings.json"
        zed = Path(os.environ.get("XDG_CONFIG_HOME", h / ".config")) / "zed/settings.json"
    else:
        xdg = Path(os.environ.get("XDG_CONFIG_HOME", h / ".config"))
        vscode_user = xdg / "Code/User/settings.json"
        zed = xdg / "zed/settings.json"
    xdg_generic = Path(os.environ.get("XDG_CONFIG_HOME", h / ".config")) / "mcp.json"
    return [
        ("windsurf",    h / ".codeium/windsurf/mcp_config.json"),
        ("zed",         zed),
        ("lmstudio",    h / ".lmstudio/mcp.json"),
        ("generic",     xdg_generic),
        ("vscode_user", vscode_user),
    ]


def _build_mcp_finding(host: str, config_basename: str, config_sha: str,
                        name, spec: dict, running: list) -> dict:
    """Same finding shape as _parse_one_config's — locked to it by
    test_mcp_config_scan.py exercising both."""
    transport = str(spec.get("type") or spec.get("transport") or "stdio")[:24]
    cmd_base = _command_basename(spec.get("command"))
    proc_running = (transport == "stdio" and bool(cmd_base)
                     and any(cmd_base.lower() in r.lower() for r in running))
    return {
        "type":             "mcp_server",
        "mcp_host":         host,
        "config_basename":  config_basename,
        "config_sha256":    config_sha,
        "server_name":      str(name)[:120],
        "command_basename": cmd_base,
        "arg_flags":        _arg_flags_only(spec.get("args")),
        "env_keys_present": _env_keys_only(spec.get("env")),
        "transport":        transport,
        "mcp_server_url":   str(spec.get("url", ""))[:200] if transport != "stdio" else "",
        "process_running":  proc_running,
    }


def _servers_from_document(data: dict, host: str) -> dict:
    """Pull the raw servers dict out of a parsed config, per host dialect."""
    if host == "vscode_user":
        mcp_block = data.get("mcp")
        servers = mcp_block.get("servers") if isinstance(mcp_block, dict) else None
    elif host == "zed":
        servers = data.get("context_servers")
    else:
        servers = data.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


def _parse_extra_single_host(host: str, path: Path, running: list) -> list:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    servers = _servers_from_document(data, host)
    if not servers:
        return []
    config_sha = _hash_file_bytes(path)
    out: list = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        finding = _build_mcp_finding(host, path.name, config_sha, name, spec, running)
        safe = _safe_finding(finding)
        if not _has_unredacted_secret(safe):
            out.append(safe)
    return out


def _parse_vscode_project_configs(running: list) -> list:
    """Project-scope VS Code config lives per-repo — walk DISCOVERED_REPOS
    the way scan_tools_code.py.frag does."""
    out: list = []
    for repo in DISCOVERED_REPOS:
        repo_path = Path(str(repo.get("path_safe", "")).replace("~", str(Path.home()), 1))
        cfg = repo_path / ".vscode" / "mcp.json"
        if not cfg.exists():
            continue
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:
            continue
        servers = data.get("servers") if isinstance(data, dict) else None
        if not isinstance(servers, dict) or not servers:
            continue
        config_sha = _hash_file_bytes(cfg)
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            finding = _build_mcp_finding("vscode_project", cfg.name, config_sha, name, spec, running)
            safe = _safe_finding(finding)
            if not _has_unredacted_secret(safe):
                out.append(safe)
    return out


def scan_mcp_extra_hosts(running: list) -> list:
    """Called from scan_mcp_configs(). Exception-safe by construction —
    matches scan_mcp_configs()'s own per-host try/except."""
    findings: list = []
    for host, path in _mcp_extra_single_paths():
        try:
            findings.extend(_parse_extra_single_host(host, path, running))
        except Exception:
            continue
    try:
        findings.extend(_parse_vscode_project_configs(running))
    except Exception:
        pass
    return findings
