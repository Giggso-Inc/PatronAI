# =============================================================
# FILE: src/retina/collector.py
# VERSION: 1.2.0
# UPDATED: 2026-11-10
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
# D2 note: scan_mcp_configs.py.frag v2.0.0+ actively enumerates tools via
# the MCP tools/list call (stdio: subprocess with 4s timeout; HTTP: POST
# with 3s timeout). The `tools` field is now populated on most findings.
# Servers that fail to start or time out produce an empty tools list —
# D2 will be partial but never causes scan failure. When `tools` is absent
# on older findings the collector falls back to [] gracefully.
#
# All extraction is best-effort — missing fields produce empty lists,
# never exceptions.
#
# DEPENDS: stdlib only
# AUDIT LOG:
#   v1.0.0  2026-09-02  Initial. RavenHub Card — Patron side.
#   v1.1.0  2026-09-02  D1 now includes transport type per spec.
#                       D2 limitation documented.
#   v1.2.0  2026-11-10  Update D2 comment: tool enumeration now active
#                       in scan_mcp_configs.py.frag v2.0.0.
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
                # D2: tool names — populated by scan_mcp_configs v2.0.0+ which
                # calls tools/list on each server (stdio: 4s timeout, HTTP: 3s).
                # Servers that time out or fail to start produce an empty list;
                # older scan payloads without the field also fall back to [].
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
