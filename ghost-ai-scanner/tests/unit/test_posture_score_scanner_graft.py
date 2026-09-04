# =============================================================
# FILE: tests/unit/test_posture_score_scanner_graft.py
# PROJECT: PatronAI — scanner graft, Phase 6
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Lock the posture_score.py fix this phase's review found:
#          c_approved_tools and c_provider_count both count/dedup by
#          `provider` generically, and without _ai_tool_findings() a
#          browser_extension or plain (non-AI) declared_dependency
#          finding would silently count as an "unapproved AI
#          provider," dragging both scores down for inventory that
#          was never an AI-tool signal in the first place. This file
#          is also the first test coverage posture_score.py has had
#          at all — scoped to the fix, not full coverage of the
#          pre-existing 452-line module.
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial.
# =============================================================

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

from scoring.posture_score import (
    c_approved_tools, c_provider_count, c_high_findings,
    _ai_tool_findings,
)


def _finding(category: str, provider: str, **overrides) -> dict:
    base = {
        "outcome": "ENDPOINT_FINDING", "category": category, "provider": provider,
        "email": "alice@acme.com", "status": "open", "severity": "LOW",
    }
    base.update(overrides)
    return base


# ── _ai_tool_findings ────────────────────────────────────────────

def test_browser_extension_excluded():
    events = [_finding("browser_extension", "ext:Google Chrome:abc123")]
    assert _ai_tool_findings(events) == []


def test_hardcoded_secret_excluded():
    events = [_finding("hardcoded_secret", "secret:aws:~/repo:config.py:14")]
    assert _ai_tool_findings(events) == []


def test_non_ai_declared_dependency_excluded():
    events = [_finding("declared_dependency", "dep:python:flask:~/repo", is_ai_related=False)]
    assert _ai_tool_findings(events) == []


def test_ai_related_declared_dependency_kept():
    events = [_finding("declared_dependency", "dep:python:langchain:~/repo", is_ai_related=True)]
    assert len(_ai_tool_findings(events)) == 1


def test_legacy_categories_unaffected():
    events = [_finding("browser", "openai.com"), _finding("mcp_server", "mcp:claude_desktop:fs")]
    assert len(_ai_tool_findings(events)) == 2


# ── c_approved_tools — the actual regression scenario ────────────

def test_browser_extension_does_not_drag_down_approved_tools_score():
    """Before the fix: this single finding would count as 1 unapproved
    event out of 1 total, scoring 0/30. After: excluded entirely, no
    events left to judge -> full 30 (the module's own
    "no_events_in_period" convention)."""
    events = [_finding("browser_extension", "ext:Google Chrome:abc123")]
    earned, detail = c_approved_tools(events, approved=set())
    assert earned == 30
    assert detail["reason"] == "no_events_in_period"


def test_flask_dependency_does_not_drag_down_approved_tools_score():
    events = [_finding("declared_dependency", "dep:python:flask:~/repo", is_ai_related=False)]
    earned, _ = c_approved_tools(events, approved=set())
    assert earned == 30


def test_unapproved_ai_provider_still_correctly_penalised():
    """The fix must not blunt the score's real job — an actual
    unapproved AI provider (a plain `browser` finding, not one of the
    three new categories) still costs points."""
    events = [_finding("browser", "some-unapproved-ai-tool.example.com")]
    earned, detail = c_approved_tools(events, approved={"openai.com"})
    assert earned == 0
    assert detail["unapproved_providers"] == ["some-unapproved-ai-tool.example.com"]


def test_ai_related_dependency_can_still_count_as_unapproved():
    """An is_ai_related dependency IS real AI-tool signal — it should
    still be judged against the approved list, not silently excluded."""
    events = [_finding("declared_dependency", "dep:python:langchain:~/repo", is_ai_related=True)]
    earned, detail = c_approved_tools(events, approved=set())
    assert earned == 0
    assert detail["unapproved_providers"] == ["dep:python:langchain:~/repo"]


# ── c_provider_count — user side AND org baseline must match ─────

def test_provider_count_excludes_non_ai_tool_categories_on_both_sides():
    user_events = [
        _finding("browser", "openai.com"),
        _finding("browser_extension", "ext:Chrome:a"),
        _finding("hardcoded_secret", "secret:aws:x"),
    ]
    org_events = [
        _finding("browser", "openai.com"),
        _finding("browser_extension", "ext:Chrome:a"),
    ]
    earned, detail = c_provider_count(user_events, org_events)
    # Only the one real AI provider counts on each side -> ratio 1.0 -> full 5.
    assert earned == 5


# ── no_high_findings already covers hardcoded_secret via CRITICAL ─

def test_hardcoded_secret_critical_zeroes_high_findings_component():
    """No code change was needed here — hardcoded_secret's CRITICAL
    severity (set in Phase 3) already triggers the existing
    any-open-CRITICAL rule. This test proves that pre-existing
    behaviour actually covers the new category, rather than assuming
    it from reading the code."""
    events = [_finding("hardcoded_secret", "secret:aws:x", severity="CRITICAL")]
    earned, detail = c_high_findings(events)
    assert earned == 0
    assert detail["open_critical"] == 1
