# =============================================================
# FILE: tests/unit/test_ravenhub_shadow_by_tool.py
# VERSION: 1.0.0
# UPDATED: 2026-08-17
# OWNER: Giggso Inc
# PURPOSE: Lock routers/ravenhub.py::_shadow_by_tool — the category
#          aggregation behind RavenHub's "Shadow AI By Tools" widget,
#          moved here from the Hub's /dashboard-overview/shadow-by-tool.
#          The Hub version read mcp_governance_notices (MCP servers only)
#          and recovered a category by substring-matching the tool NAME,
#          checking "MCPs" last — so `mcp:claude_desktop:weather` matched
#          "claude" and was reported as a foundation model, and prod
#          showed Browser AI=2 (both MCP servers) with MCPs=0.
#          These tests pin the properties that make the replacement
#          trustworthy: category comes from detection evidence, counts
#          are DISTINCT tools/users, totals do not double-count, and an
#          unmapped category is reported rather than silently absorbed.
#          Pure; no S3/DB — plain dicts in, dict out.
# AUDIT LOG:
#   v1.0.0  2026-08-17  Initial — accompanies the /ravenhub/shadow/by-tool
#                       endpoint added in ravenhub.py.
# =============================================================

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from routers.ravenhub import (  # noqa: E402
    _shadow_by_tool, _tool_name_of,
    _SHADOW_DISPLAY_ORDER, _PATRON_CATEGORY_TO_DISPLAY,
)


def _ev(**kw) -> dict:
    """Event dict with sane defaults, overridable per test. Mirrors the
    helper in test_ravenhub.py."""
    base = {
        "outcome": "ENDPOINT_FINDING", "severity": "MEDIUM",
        "provider": "claude.ai", "category": "browser",
        "owner": "a@giggso.com", "email": "a@giggso.com",
        "timestamp": "2026-08-17T08:00:00Z",
    }
    base.update(kw)
    return base


def _by_cat(result: dict) -> dict:
    return {c["category"]: c for c in result["categories"]}


# ── the bug this endpoint exists to fix ───────────────────────────────────────

def test_mcp_servers_land_in_mcps_not_foundation_model():
    """The whole point. Every one of these is a real MCP server, and every one
    was misreported by the Hub's name-matching classifier — the four
    claude_desktop rows as "Foundational Model" (the name contains "claude",
    which is the HOST app, not the tool) and the cursor row as "Code
    Assistant". Category must come from the detection, not the string."""
    events = [
        _ev(provider="mcp:claude_desktop:weather",    category="mcp_server"),
        _ev(provider="mcp:claude_desktop:zohoCRM",    category="mcp_server"),
        _ev(provider="mcp:claude_desktop:local_files", category="mcp_server"),
        _ev(provider="mcp:claude_desktop:shay_chat",  category="mcp_server"),
        _ev(provider="mcp:cursor:zoho-books",         category="mcp_server"),
    ]
    cats = _by_cat(_shadow_by_tool(events))
    assert cats["MCPs"]["tools_count"] == 5
    assert cats["Browser AI"]["tools_count"] == 0
    assert cats["Others"]["tools_count"] == 0


def test_foundation_model_and_code_assistant_are_not_offered():
    """Removed deliberately, not merely unpopulated: neither is establishable
    from detection evidence, so they must not reappear as empty bars that
    imply we looked and found none."""
    assert _SHADOW_DISPLAY_ORDER == ["MCPs", "Vector DB", "Browser AI", "Others"]
    assert "Foundational Model" not in _SHADOW_DISPLAY_ORDER
    assert "Code Assistant" not in _SHADOW_DISPLAY_ORDER
    assert "Foundational Model" not in _PATRON_CATEGORY_TO_DISPLAY.values()
    assert "Code Assistant" not in _PATRON_CATEGORY_TO_DISPLAY.values()


# ── counting ──────────────────────────────────────────────────────────────────

def test_counts_distinct_tools_and_users_not_events():
    """One developer hitting one vector DB forty times is one tool and one
    user. The axis says tools/users, so counting events would overstate both
    by an order of magnitude on a busy day."""
    events = [_ev(provider="vdb:chroma:Chroma", category="vector_db",
                  owner="a@giggso.com", email="a@giggso.com")] * 40
    result = _shadow_by_tool(events)
    cats = _by_cat(result)
    assert cats["Vector DB"]["tools_count"] == 1
    assert cats["Vector DB"]["users_count"] == 1
    assert result["total_tools"] == 1
    assert result["total_users"] == 1


def test_totals_are_a_union_not_a_sum_of_bars():
    """A developer active in three categories is ONE user org-wide. Summing
    the per-category user counts would report 3."""
    events = [
        _ev(provider="mcp:x:y",          category="mcp_server",  owner="a@x.com", email="a@x.com"),
        _ev(provider="vdb:chroma:Chroma", category="vector_db",  owner="a@x.com", email="a@x.com"),
        _ev(provider="cursor.com",        category="browser",    owner="a@x.com", email="a@x.com"),
    ]
    result = _shadow_by_tool(events)
    assert sum(c["users_count"] for c in result["categories"]) == 3   # per-bar
    assert result["total_users"] == 1                                 # reality
    assert result["total_tools"] == 3


def test_every_category_is_returned_even_when_empty():
    """Zero-filled so the chart's x-axis does not reshuffle between periods."""
    result = _shadow_by_tool([_ev(provider="mcp:x:y", category="mcp_server")])
    assert [c["category"] for c in result["categories"]] == _SHADOW_DISPLAY_ORDER


def test_no_events_returns_zeros_not_an_empty_list():
    result = _shadow_by_tool([])
    assert [c["category"] for c in result["categories"]] == _SHADOW_DISPLAY_ORDER
    assert all(c["tools_count"] == 0 and c["users_count"] == 0
               for c in result["categories"])
    assert result["total_tools"] == 0
    assert result["uncategorised_tools"] == 0


# ── mapping and its edges ─────────────────────────────────────────────────────

def test_secondary_evidence_types_fold_into_others():
    """ide_plugin / process / shell_history / tool_registration are real
    detections with no bar of their own — they belong in Others, and must NOT
    count as uncategorised, which is reserved for genuinely unknown input."""
    events = [
        _ev(provider="continue.continue-2.0.0-linux", category="ide_plugin"),
        _ev(provider="ollama",                        category="process"),
        _ev(provider="shell:pip install openai",      category="shell_history"),
        _ev(provider="tools:Giggso-AI-ML",            category="tool_registration"),
    ]
    result = _shadow_by_tool(events)
    assert _by_cat(result)["Others"]["tools_count"] == 4
    assert result["uncategorised_tools"] == 0


def test_unknown_category_is_reported_not_silently_absorbed():
    """A category the scanner starts emitting that we have not mapped still
    renders (in Others) but is counted, so a growing Others bar is
    attributable instead of mysterious."""
    events = [
        _ev(provider="brand-new-thing", category="some_future_category"),
        _ev(provider="mcp:x:y",         category="mcp_server"),
    ]
    result = _shadow_by_tool(events)
    assert _by_cat(result)["Others"]["tools_count"] == 1
    assert result["uncategorised_tools"] == 1


def test_resolved_findings_are_excluded():
    """Matches posture_breakdown's contract — a resolved signature is not
    current shadow AI."""
    events = [
        _ev(provider="mcp:live:one", category="mcp_server"),
        _ev(provider="mcp:done:two", category="mcp_server", status="resolved"),
    ]
    assert _by_cat(_shadow_by_tool(events))["MCPs"]["tools_count"] == 1


def test_rows_with_no_resolvable_tool_name_are_skipped():
    """An unnamed row would otherwise become a single phantom '' tool that
    inflates whichever bar it lands in."""
    events = [
        _ev(provider="", dst_domain="", category="mcp_server"),
        _ev(provider="mcp:real:one",    category="mcp_server"),
    ]
    result = _shadow_by_tool(events)
    assert _by_cat(result)["MCPs"]["tools_count"] == 1
    assert result["total_tools"] == 1


def test_tool_name_falls_back_to_domain():
    """A network row can match a domain without resolving a named provider;
    dropping it would lose a real detection."""
    assert _tool_name_of({"provider": "", "dst_domain": "api.openai.com"}) == "api.openai.com"
    assert _tool_name_of({"provider": "ollama", "dst_domain": "x"}) == "ollama"
    assert _tool_name_of({}) == ""


def test_missing_owner_counts_the_tool_but_no_user():
    """Attribution can be absent; the tool is still shadow AI. Counting an
    empty owner as a user would invent a person."""
    events = [_ev(provider="mcp:x:y", category="mcp_server", owner="", email="")]
    cats = _by_cat(_shadow_by_tool(events))
    assert cats["MCPs"]["tools_count"] == 1
    assert cats["MCPs"]["users_count"] == 0
