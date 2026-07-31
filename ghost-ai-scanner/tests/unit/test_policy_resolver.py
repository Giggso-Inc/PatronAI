# =============================================================
# FILE: tests/unit/test_policy_resolver.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: PolicyContext built from the existing CSV rows (Phase A,
#          org scope). Pure; no I/O.
# =============================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from scoring.policy_resolver import context_from_csv


def test_builds_org_scopes_from_csv_rows():
    ctx = context_from_csv(
        authorized=[{"name": "GitHub Copilot", "domain_pattern": "copilot.github.com", "notes": ""}],
        authorized_code=[{"name": "LangChain", "pattern": "langchain", "type": "framework"}],
        unauthorized_custom=[{"name": "Sketchy", "domain": "sketchy.ai", "severity": "HIGH"}],
        unauthorized_code_custom=[{"name": "AutoGen", "pattern": "autogen"}],
        giggso_baseline=[{"name": "OpenAI", "domain": "*.openai.com", "severity": "HIGH"}],
    )
    assert "copilot.github.com" in ctx.org_approve
    assert "langchain" in ctx.org_approve
    assert "sketchy.ai" in ctx.org_deny
    assert "autogen" in ctx.org_deny
    # ADR_2026-07-31: no separate giggso_deny tier — starter/baseline deny
    # content folds straight into org_deny like any other org-deny source.
    assert "*.openai.com" in ctx.org_deny
    # Project/user scopes stay empty here (DB-only scopes).
    assert ctx.project_approve == set()
    assert ctx.user_ack == set()


def test_comment_rows_and_blanks_are_skipped():
    ctx = context_from_csv(
        authorized=[{"name": "# EXAMPLE ROW", "domain_pattern": ""},
                    {"name": "", "domain_pattern": "  "}],
    )
    assert ctx.org_approve == set()


def test_patterns_are_normalised_lowercase():
    ctx = context_from_csv(authorized=[{"name": "Claude", "domain_pattern": "Claude.AI"}])
    assert "claude.ai" in ctx.org_approve
    assert "claude" in ctx.org_approve
