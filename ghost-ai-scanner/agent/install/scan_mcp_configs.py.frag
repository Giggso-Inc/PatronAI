# =============================================================
# FRAGMENT: scan_mcp_configs.py.frag
# PROJECT: PatronAI — Phase 1A
# VERSION: 2.0.0
# UPDATED: 2026-11-10
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Real MCP-server inventory. Reads the MCP config JSONs that
#          AI clients (Claude Desktop, Claude Code, Cursor, Continue,
#          Cline) keep on disk. Emits one `mcp_server` finding per
#          server defined, with redacted metadata (server name + command
#          basename + arg FLAGS only — no values) and a SHA-256 of the
#          parent file for change detection. Also attempts active MCP
#          tool enumeration (tools/list) for each server so D2 is
#          populated; best-effort, never blocks the scan.
#          Privacy: every finding passes through the shared redactor;
#          any finding still carrying a secret after redaction is
#          dropped entirely. Tool names are plain identifiers and do
#          not trigger the secret redactor.
# AUDIT LOG:
#   v1.0.0  2026-04-26  Initial. Phase 1A.
#   v2.0.0  2026-11-10  D1: add ~/.claude/settings.json (Claude Code).
#                       D2: active MCP tools/list enumeration via stdio
#                       and HTTP transports. 4-second hard timeout per
#                       server; never crashes the scan.
# =============================================================

import hashlib
import urllib.request as _urllib_req

# Per-host config locations — broad enough to cover the common installs.
# Order matters only for deterministic output; not security-relevant.
def _mcp_config_paths() -> list:
    """Per-OS list of (host_label, config_path) candidates."""
    h = Path.home()
    # ~/.claude/settings.json is cross-platform — Claude Code uses the
    # same path on macOS, Linux, and Windows (rooted at $HOME).
    claude_code_paths = [
        ("claude_code",       h / ".claude/settings.json"),
        ("claude_code_local", h / ".claude/settings.local.json"),
    ]
    if OS_NAME == "darwin":
        return [
            ("claude_desktop", h / "Library/Application Support/Claude/claude_desktop_config.json"),
            ("cursor",         h / ".cursor/mcp.json"),
            ("continue",       h / ".continue/config.json"),
            ("cline",          h / ".config/Cline/mcp_settings.json"),
        ] + claude_code_paths
    if OS_NAME == "windows":
        appdata = Path(os.environ.get("APPDATA", h / "AppData/Roaming"))
        return [
            ("claude_desktop", appdata / "Claude/claude_desktop_config.json"),
            ("cursor",         h / ".cursor/mcp.json"),
            ("continue",       h / ".continue/config.json"),
            ("cline",          h / ".config/Cline/mcp_settings.json"),
        ] + claude_code_paths
    # linux + other unix
    return [
        ("claude_desktop", h / ".config/Claude/claude_desktop_config.json"),
        ("cursor",         h / ".cursor/mcp.json"),
        ("continue",       h / ".continue/config.json"),
        ("cline",          h / ".config/Cline/mcp_settings.json"),
    ] + claude_code_paths


def _hash_file_bytes(p: Path) -> str:
    """Compute SHA-256 of a file's raw bytes, or '' on read error."""
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except Exception:
        return ""


def _arg_flags_only(args) -> list:
    """Take a list of MCP server args; keep only flag-shaped tokens
    (start with '-'). Drop values, paths, URLs, anything that could
    leak. Output capped at 12 flags per server."""
    if not isinstance(args, list):
        return []
    flags = [a for a in args if isinstance(a, str) and a.startswith("-")]
    return flags[:12]


def _env_keys_only(env) -> list:
    """Take a dict of env vars; return only the KEYS, never values."""
    if not isinstance(env, dict):
        return []
    return sorted(env.keys())[:24]


def _command_basename(cmd) -> str:
    """Reduce a full command path to its leaf executable name."""
    if not isinstance(cmd, str) or not cmd:
        return ""
    return Path(cmd).name


def _enumerate_mcp_tools(spec: dict, timeout: float = 4.0) -> list:
    """Best-effort MCP tools/list enumeration for one server entry.

    stdio transport: spawns the server process with its full command +
    args + env, sends the three-message MCP handshake (initialize →
    notifications/initialized → tools/list) over stdin, reads
    newline-delimited JSON-RPC 2.0 from stdout. Returns tool names only.

    http/sse transport: POSTs tools/list to spec["url"] with a 3-second
    timeout.

    Returns [] on timeout, missing command, or any error — never raises
    and never blocks the scan for more than `timeout` seconds.
    """
    transport = str(spec.get("transport", "stdio")).lower().strip()

    # ── HTTP / SSE transport ──────────────────────────────────────────
    if transport in ("http", "sse", "streamable-http"):
        url = str(spec.get("url") or "").strip()
        if not url:
            return []
        try:
            body = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/list", "params": {},
            }).encode()
            req = _urllib_req.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with _urllib_req.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode(errors="replace"))
                return [
                    str(t.get("name", "")).strip()[:80]
                    for t in (data.get("result", {}).get("tools") or [])
                    if t.get("name")
                ]
        except Exception:
            return []

    # ── stdio transport (default) ─────────────────────────────────────
    if transport not in ("stdio", ""):
        return []
    cmd = spec.get("command")
    if not cmd or not isinstance(cmd, str):
        return []
    args = spec.get("args") or []
    if not isinstance(args, list):
        args = []

    # Pass env vars from the config so servers that need API keys to
    # start will respond. These run on the user's own machine under their
    # own OS account — same privileges as the scan itself.
    proc_env = dict(os.environ)
    raw_env = spec.get("env")
    if isinstance(raw_env, dict):
        for k, v in raw_env.items():
            if isinstance(k, str) and isinstance(v, str):
                proc_env[k] = v

    # MCP wire protocol: newline-delimited JSON-RPC 2.0.
    # Send initialize + initialized notification + tools/list all at
    # once so a single communicate() call covers the full exchange.
    msgs = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05",
                               "capabilities": {},
                               "clientInfo": {"name": "patronai-scan",
                                              "version": "1.0"}}}),
        json.dumps({"jsonrpc": "2.0",
                    "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2,
                    "method": "tools/list", "params": {}}),
    ]) + "\n"

    try:
        proc = subprocess.Popen(
            [cmd] + [str(a) for a in args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=proc_env,
        )
        try:
            stdout_bytes, _ = proc.communicate(
                input=msgs.encode(), timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return []

        tools: list = []
        for line in stdout_bytes.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if msg.get("id") == 2 and "result" in msg:
                    for t in (msg["result"].get("tools") or []):
                        name = str(t.get("name", "")).strip()[:80]
                        if name:
                            tools.append(name)
            except Exception:
                continue
        return tools
    except Exception:
        return []
    finally:
        try:
            proc.kill()  # no-op if already exited
        except Exception:
            pass


def _parse_one_config(host: str, path: Path) -> list:
    """Read one MCP config JSON; emit a finding per server. On any
    parse failure, return empty list (don't crash the scan)."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    servers = data.get("mcpServers") or {}
    if not isinstance(servers, dict) or not servers:
        return []
    config_sha = _hash_file_bytes(path)
    out: list = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        # Enumerate tools before redacting the spec — needs full
        # command/args/env. Tool names are plain identifiers (e.g.
        # "read_file") and do not trigger the secret redactor.
        tools = _enumerate_mcp_tools(spec)
        finding = {
            "type":             "mcp_server",
            "mcp_host":         host,
            "config_basename":  path.name,
            "config_sha256":    config_sha,
            "server_name":      str(name)[:120],
            "command_basename": _command_basename(spec.get("command")),
            "arg_flags":        _arg_flags_only(spec.get("args")),
            "env_keys_present": _env_keys_only(spec.get("env")),
            "transport":        str(spec.get("transport", "stdio"))[:24],
            "tools":            tools,
        }
        safe = _safe_finding(finding)
        if _has_unredacted_secret(safe):
            continue                                  # privacy gate — drop
        out.append(safe)
    return out


def scan_mcp_configs() -> list:
    """Walk every known MCP config path; emit `mcp_server` findings.
    Returns [] cleanly if no host is installed — common on locked-down
    fleets where neither Claude Desktop nor Cursor is in use."""
    findings: list = []
    for host, path in _mcp_config_paths():
        try:
            findings.extend(_parse_one_config(host, path))
        except Exception:
            continue                                  # never crash a scan
    return findings
