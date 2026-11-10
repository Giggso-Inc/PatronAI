# =============================================================
# FRAGMENT: scan_mcp_enumerate.py.frag
# PROJECT: PatronAI — Phase 1A
# VERSION: 1.0.0
# UPDATED: 2026-11-10
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Active MCP tool enumeration helper used by scan_mcp_configs.
#          Provides _enumerate_mcp_tools(spec) — calls tools/list on
#          each discovered MCP server so D2 is populated with real tool
#          names. Best-effort: always returns [] on timeout or error,
#          never raises, never blocks the scan for more than timeout secs.
#
#          Transport coverage:
#            stdio        — spawn process, full 3-message MCP handshake,
#                           4-second hard timeout via communicate().
#            http/sse/
#            streamable-  — POST tools/list to spec["url"], 3-second
#            http           urllib timeout.
#            other        — skip; return [].
#
# DEPENDS: json, os, subprocess (scan_header globals); urllib.request
# AUDIT LOG:
#   v1.0.0  2026-11-10  Extracted from scan_mcp_configs.py.frag v2.0.0
#                       to keep both fragments under the 150-LOC cap.
# =============================================================

import urllib.request as _urllib_req


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
