# =============================================================
# FILE: src/retina/collector.py
# VERSION: 1.1.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Extract the seven retina dimensions (D1-D7) from a raw
#          endpoint scan payload already stored in S3. Maps the
#          PatronAI finding categories onto the canonical dimensions
#          defined by the RavenHub Card spec.
#
# Mapping:
#   D1  MCP Servers        finding.type == "mcp_server"   -> "server_name:transport"
#   D2  MCP Tools          finding.type == "mcp_server"   -> "server/tool" (if present)
#   D3  IDE Plugins        finding.type == "ide_plugin"   -> plugin_id
#   D4  Agent Processes    finding.type == "process"      -> name
#   D5  Frameworks/Models  finding.type == "package"      -> "manager:name"
#   D6  AI Destinations    finding.type == "browser"      -> domain
#   D7  Config Digests     finding.type == "mcp_server"   -> "basename:sha256"
#
# D1 note: transport (stdio|http) is included in the D1 value so two MCP
# servers with the same name but different transports produce distinct
# entries, as required by the spec.
#
# D2 note: PatronAI's current agent scripts parse MCP config files but do
# not call tools/list on each server (that requires an active MCP connection,
# not just config parsing). The `tools` field will be absent from most
# mcp_server findings, so D2 will typically be empty until the agent adds
# tool enumeration. The hash will still detect D1/D7 drifts correctly.
#
# All extraction is best-effort — missing fields produce empty lists,
# never exceptions.
#
# DEPENDS: stdlib only
# AUDIT LOG:
#   v1.0.0  2026-09-02  Initial. RavenHub Card — Patron side.
#   v1.1.0  2026-09-02  D1 now includes transport type per spec.
#                       D2 limitation documented.
# =============================================================

from __future__ import annotations


def _safe(value: object, max_len: int = 256) -> str:
    """Return a safe, stripped string from any value. Never raises."""
    try:
        return str(value or "").strip()[:max_len]
    except Exception:
        return ""


def extract_dimensions(scan: dict) -> dict[str, list[str]]:
    """Extract D1-D7 from a raw endpoint scan dict (the agent's latest.json).

    scan must have a "findings" key that is a list of finding dicts.
    Returns a dict with keys d1-d7, each a list of raw (un-normalised)
    strings. The caller passes this to normaliser.normalise() before hashing.
    """
    findings: list[dict] = []
    try:
        findings = scan.get("findings") or []
    except Exception:
        pass

    d1: list[str] = []
    d2: list[str] = []
    d3: list[str] = []
    d4: list[str] = []
    d5: list[str] = []
    d6: list[str] = []
    d7: list[str] = []

    for f in findings:
        try:
            ftype = _safe(f.get("type"))

            if ftype == "mcp_server":
                # D1: "server_name:transport" — transport distinguishes stdio vs http.
                # Two servers with the same name on different transports are different
                # MCP surfaces and must produce distinct D1 entries (spec requirement).
                server    = _safe(f.get("server_name") or f.get("mcp_host"))
                transport = _safe(f.get("transport", ""))
                if server:
                    d1.append(f"{server}:{transport}" if transport else server)
                # D2: tool entries — only populated when the agent has enumerated tools
                # via the MCP protocol (tools/list). Most mcp_server findings from
                # config parsing will not have a `tools` field, so D2 is typically
                # empty until active tool enumeration is added to the agent scripts.
                for tool in (f.get("tools") or []):
                    t = _safe(tool)
                    if t:
                        d2.append(f"{server}/{t}" if server else t)
                # D7: "basename:sha256" config digest
                sha = _safe(f.get("config_sha256"))
                base = _safe(f.get("config_basename"))
                if base and sha:
                    d7.append(f"{base}:{sha}")
                elif sha:
                    d7.append(sha)

            elif ftype == "ide_plugin":
                pid = _safe(f.get("plugin_id") or f.get("process_name"))
                if pid:
                    d3.append(pid)

            elif ftype == "process":
                name = _safe(f.get("name") or f.get("process_name"))
                if name:
                    d4.append(name)

            elif ftype == "package":
                manager = _safe(f.get("manager", "pkg"))
                name = _safe(f.get("name") or f.get("process_name"))
                if name:
                    d5.append(f"{manager}:{name}" if manager else name)

            elif ftype == "browser":
                domain = _safe(f.get("domain") or f.get("dst_domain"))
                if domain:
                    d6.append(domain)

        except Exception:
            continue

    return {"d1": d1, "d2": d2, "d3": d3,
            "d4": d4, "d5": d5, "d6": d6, "d7": d7}
