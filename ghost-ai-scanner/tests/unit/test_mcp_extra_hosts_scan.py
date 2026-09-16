# =============================================================
# FILE: tests/unit/test_mcp_extra_hosts_scan.py
# PROJECT: PatronAI — scanner graft, Phase 4
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Lock scan_mcp_configs_extra_hosts.py.frag's contract:
#          - no config anywhere -> [] for every source
#          - vscode_user: nested "mcp":{"servers":{}} shape, distinct
#            from every other host's flat mcpServers
#          - vscode_project: walks DISCOVERED_REPOS, root key
#            "servers" (not mcpServers), one per repo
#          - windsurf / zed / lmstudio / generic: correct path + root
#            key per host (zed's "context_servers" is the one that
#            differs from the flat mcpServers convention)
#          - every emitted finding is the same `mcp_server` shape
#            scan_mcp_configs.py.frag's own findings use — locked by
#            a direct field comparison, not just a smoke assertion
#          - redaction still gates every finding here too
#          - a malformed config file anywhere is skipped, not raised
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial.
# =============================================================

import json
import os
import re
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


def _run(home: Path, discovered_repos: list | None = None) -> list:
    ns: dict = {
        "re": re, "Path": Path, "os": os, "json": json,
        "OS_NAME": "darwin",
        "AGENT_DIR": home / ".patronai",
        "DISCOVERED_REPOS": discovered_repos or [],
    }
    real_home = Path.home
    Path.home = staticmethod(lambda: home)  # type: ignore
    try:
        for frag in ("scan_redactor.py.frag", "scan_mcp_configs.py.frag",
                     "scan_mcp_configs_extra_hosts.py.frag"):
            exec(compile((FRAGS / frag).read_text(encoding="utf-8"), frag, "exec"), ns)
        return ns["scan_mcp_extra_hosts"]([])
    finally:
        Path.home = real_home  # type: ignore


def test_no_configs_means_no_findings(tmp_path):
    assert _run(tmp_path) == []


def test_vscode_user_nested_shape(tmp_path):
    p = tmp_path / "Library/Application Support/Code/User/settings.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "mcp": {"servers": {"filesystem": {
            "command": "/usr/local/bin/npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice"],
        }}}
    }), encoding="utf-8")
    out = _run(tmp_path)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "mcp_server"
    assert f["mcp_host"] == "vscode_user"
    assert f["server_name"] == "filesystem"
    assert f["command_basename"] == "npx"


def test_vscode_user_flat_mcpservers_is_not_matched(tmp_path):
    """vscode_user is specifically the nested "mcp":{"servers":{}} shape
    — a flat top-level mcpServers key (a different host's convention)
    must not accidentally match here."""
    p = tmp_path / "Library/Application Support/Code/User/settings.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"mcpServers": {"filesystem": {"command": "npx"}}}), encoding="utf-8")
    assert _run(tmp_path) == []


def test_vscode_project_walks_discovered_repos(tmp_path):
    repo_dir = tmp_path / "projects" / "repo1"
    (repo_dir / ".vscode").mkdir(parents=True)
    (repo_dir / ".vscode" / "mcp.json").write_text(json.dumps({
        "servers": {"github": {"command": "docker", "args": ["run", "-i", "ghcr.io/github/mcp"]}}
    }), encoding="utf-8")
    repos = [{"path_safe": "~/projects/repo1", "name": "repo1"}]
    out = _run(tmp_path, discovered_repos=repos)
    assert len(out) == 1
    f = out[0]
    assert f["mcp_host"] == "vscode_project"
    assert f["server_name"] == "github"
    assert f["command_basename"] == "docker"


def test_vscode_project_no_config_in_repo_means_no_finding(tmp_path):
    repo_dir = tmp_path / "projects" / "repo1"
    repo_dir.mkdir(parents=True)
    repos = [{"path_safe": "~/projects/repo1", "name": "repo1"}]
    assert _run(tmp_path, discovered_repos=repos) == []


def test_windsurf_flat_mcpservers_shape(tmp_path):
    p = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}}),
                 encoding="utf-8")
    out = _run(tmp_path)
    assert len(out) == 1
    assert out[0]["mcp_host"] == "windsurf"
    assert out[0]["server_name"] == "fetch"


def test_zed_context_servers_key(tmp_path):
    p = tmp_path / ".config" / "zed" / "settings.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"context_servers": {"postgres": {"command": "mcp-server-postgres"}}}),
                 encoding="utf-8")
    out = _run(tmp_path)
    assert len(out) == 1
    assert out[0]["mcp_host"] == "zed"
    assert out[0]["server_name"] == "postgres"


def test_zed_flat_mcpservers_key_is_ignored(tmp_path):
    """Zed's own dialect is context_servers, not mcpServers — a config
    using the wrong key for this host must not match."""
    p = tmp_path / ".config" / "zed" / "settings.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"mcpServers": {"postgres": {"command": "mcp-server-postgres"}}}),
                 encoding="utf-8")
    assert _run(tmp_path) == []


def test_lmstudio_flat_mcpservers_shape(tmp_path):
    p = tmp_path / ".lmstudio" / "mcp.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"mcpServers": {"sqlite": {"command": "mcp-server-sqlite"}}}), encoding="utf-8")
    out = _run(tmp_path)
    assert len(out) == 1
    assert out[0]["mcp_host"] == "lmstudio"


def test_generic_xdg_config_shape(tmp_path):
    p = tmp_path / ".config" / "mcp.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"mcpServers": {"time": {"command": "mcp-server-time"}}}), encoding="utf-8")
    out = _run(tmp_path)
    assert len(out) == 1
    assert out[0]["mcp_host"] == "generic"


def test_finding_shape_matches_scan_mcp_configs_own_findings(tmp_path):
    """Both files must produce identically-shaped mcp_server dicts —
    same keys, so downstream (agent_explode, dashboard) sees one
    consistent contract regardless of source."""
    p = tmp_path / ".lmstudio" / "mcp.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"mcpServers": {"time": {"command": "mcp-server-time", "args": ["--utc"]}}}),
                 encoding="utf-8")
    out = _run(tmp_path)
    expected_keys = {
        "type", "mcp_host", "config_basename", "config_sha256", "server_name",
        "command_basename", "arg_flags", "env_keys_present", "transport",
        "mcp_server_url", "process_running",
    }
    assert set(out[0].keys()) == expected_keys


def test_env_values_dropped_keys_kept(tmp_path):
    p = tmp_path / ".lmstudio" / "mcp.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"mcpServers": {"svc": {
        "command": "mcp-server", "env": {"API_KEY": "sk-should-not-appear-1234567890"}}}}),
                 encoding="utf-8")
    out = _run(tmp_path)
    dumped = json.dumps(out)
    assert "sk-should-not-appear-1234567890" not in dumped
    assert "API_KEY" in out[0]["env_keys_present"]


def test_malformed_json_is_skipped_not_raised(tmp_path):
    p = tmp_path / ".lmstudio" / "mcp.json"
    p.parent.mkdir(parents=True)
    p.write_text("not valid json {{{", encoding="utf-8")
    assert _run(tmp_path) == []


def test_multiple_sources_all_contribute(tmp_path):
    (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
    (tmp_path / ".codeium" / "windsurf" / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"a": {"command": "cmd-a"}}}), encoding="utf-8")
    (tmp_path / ".lmstudio").mkdir(parents=True)
    (tmp_path / ".lmstudio" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"b": {"command": "cmd-b"}}}), encoding="utf-8")
    out = _run(tmp_path)
    hosts = {f["mcp_host"] for f in out}
    assert hosts == {"windsurf", "lmstudio"}
