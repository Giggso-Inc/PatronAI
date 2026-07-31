# =============================================================
# FILE: tests/unit/test_provider_governance_overview.py
# VERSION: 1.0.0
# UPDATED: 2026-07-27
# OWNER: Giggso Inc
# PURPOSE: Unit tests for dashboard/ui/tabs/provider_governance.py's
#          Overview-visibility fix (2026-07-27) — a configured
#          ApprovedTool/BlacklistedTool rule with zero observed findings
#          (e.g. a RavenHub-approved MCP) must still surface in Overview,
#          and project/org-scope APPROVALS must be included in the
#          "Inherited" tiers shown at narrower scopes, not just denials.
#          Pure functions / plain dicts — no Streamlit or DB needed.
# =============================================================

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dashboard.ui.tabs.provider_governance import (
    _configured_only_providers, _augment_with_configured_only, _INHERITED_TIERS, _STATE,
)
from scoring.policy import PolicyContext


def _tool(pattern_attr, pattern):
    return SimpleNamespace(**{pattern_attr: pattern})


class TestConfiguredOnlyProviders:

    def test_approved_with_zero_findings_is_included(self):
        ap = [_tool("domain_pattern", "mcp:*:gmail")]
        result = _configured_only_providers([], ap, [])
        assert result == [{
            "provider": "mcp:*:gmail", "category": "mcp_server",
            "max_severity": "", "finding_count": 0,
        }]

    def test_denied_with_zero_findings_is_included(self):
        dn = [_tool("domain", "mcp:*:shodan")]
        result = _configured_only_providers([], [], dn)
        assert result[0]["provider"] == "mcp:*:shodan"

    def test_non_mcp_pattern_gets_unknown_category(self):
        ap = [_tool("domain_pattern", "slack.com")]
        result = _configured_only_providers([], ap, [])
        assert result[0]["category"] == "unknown"

    def test_already_observed_provider_is_not_duplicated(self):
        """If all_providers() already produced a row for this provider
        (a real finding exists), don't add a second synthetic zero-finding
        entry for the same name."""
        provs = [{"provider": "mcp:*:gmail", "category": "mcp_server",
                  "max_severity": "HIGH", "finding_count": 3}]
        ap = [_tool("domain_pattern", "mcp:*:gmail")]
        result = _configured_only_providers(provs, ap, [])
        assert result == []

    def test_no_configured_rules_returns_empty_list(self):
        assert _configured_only_providers([], [], []) == []

    def test_dedupes_same_pattern_in_both_approved_and_denied(self):
        """Shouldn't happen in practice (a pattern is either approved or
        denied, not both), but must not produce two rows if it does."""
        ap = [_tool("domain_pattern", "mcp:*:gmail")]
        dn = [_tool("domain", "mcp:*:gmail")]
        result = _configured_only_providers([], ap, dn)
        assert len(result) == 1

    def test_mixed_case_observed_provider_is_not_duplicated(self):
        """F01 (2026-07-27 review): a real observed provider with uppercase
        (agent_explode.py's _provider_for never lowercases mcp_host/
        server_name — e.g. "mcp:MyHost:Filesystem") must not spawn a
        misleading second "0 findings" ghost row for the same tool just
        because ApprovedTool.domain_pattern is stored lowercase."""
        provs = [{"provider": "mcp:MyHost:Filesystem", "category": "mcp_server",
                  "max_severity": "HIGH", "finding_count": 5}]
        ap = [_tool("domain_pattern", "mcp:myhost:filesystem")]
        result = _configured_only_providers(provs, ap, [])
        assert result == []


class TestAugmentWithConfiguredOnly:
    """This is the actual bug the user hit: _inherited_lists() filters
    strictly by tier on an OBSERVED-only list — _configured_only_providers
    (used by Overview) doesn't set a `tier` at all, so it silently didn't
    fix Inherited. This is the tier-aware version that does."""

    def test_project_approve_pattern_gets_correct_tier_and_appears(self):
        ctx = PolicyContext(project_approve={"mcp:*:gmail"})
        result = _augment_with_configured_only([], ctx)
        assert result == [{
            "provider": "mcp:*:gmail", "category": "mcp_server",
            "max_severity": "", "finding_count": 0, "tier": "project_approve",
        }]

    def test_org_approve_pattern_gets_correct_tier(self):
        ctx = PolicyContext(org_approve={"mcp:*:notion"})
        result = _augment_with_configured_only([], ctx)
        assert result[0]["tier"] == "org_approve"

    def test_user_rule_beats_project_in_computed_tier(self):
        """Sanity check that we reuse the real waterfall (policy_tier), not
        a naive first-match — ADR_2026-07-31 scope-first precedence means
        the more-specific (user) rule wins even over a project approve."""
        ctx = PolicyContext(user_deny={"evil.example.com"},
                            project_approve={"evil.example.com"})
        result = _augment_with_configured_only([], ctx)
        assert result[0]["tier"] == "user_deny"

    def test_already_observed_provider_is_not_duplicated_and_keeps_its_row(self):
        providers = [{"provider": "mcp:*:gmail", "category": "mcp_server",
                     "max_severity": "HIGH", "finding_count": 5, "tier": "project_approve"}]
        ctx = PolicyContext(project_approve={"mcp:*:gmail"})
        result = _augment_with_configured_only(providers, ctx)
        assert len(result) == 1
        assert result[0]["finding_count"] == 5   # the real observed row, untouched

    def test_mixed_case_observed_provider_is_not_duplicated(self):
        """F01 (2026-07-27 review), same fix reproduced against the
        tier-aware Inherited-tab helper: a real observed provider whose raw
        event string carries uppercase (e.g. "mcp:MyHost:Filesystem") must
        not spawn a phantom "0 findings" ghost row alongside the real one
        just because ctx's pattern sets are stored lowercase."""
        providers = [{"provider": "mcp:MyHost:Filesystem", "category": "mcp_server",
                     "max_severity": "HIGH", "finding_count": 5, "tier": "project_approve"}]
        ctx = PolicyContext(project_approve={"mcp:myhost:filesystem"})
        result = _augment_with_configured_only(providers, ctx)
        assert len(result) == 1
        assert result[0]["finding_count"] == 5

    def test_pattern_with_unknown_tier_is_still_included(self):
        """A pattern that matches nothing in ctx resolves to 'unknown' —
        still appended (harmless; _inherited_lists' own tier filter is what
        decides whether it's actually shown anywhere)."""
        ctx = PolicyContext()
        result = _augment_with_configured_only([{"provider": "other", "category": "x",
                                                  "max_severity": "", "finding_count": 1, "tier": "unknown"}], ctx)
        assert len(result) == 1   # no configured patterns at all to add

    def test_empty_context_returns_providers_unchanged(self):
        providers = [{"provider": "x", "category": "y", "max_severity": "", "finding_count": 0, "tier": "unknown"}]
        assert _augment_with_configured_only(providers, PolicyContext()) == providers


class TestInheritedTiersIncludeApprovals:

    def test_project_scope_inherits_org_approve(self):
        assert "org_approve" in _INHERITED_TIERS["project"]

    def test_user_scope_inherits_both_approve_tiers(self):
        assert "org_approve" in _INHERITED_TIERS["user"]
        assert "project_approve" in _INHERITED_TIERS["user"]

    def test_user_scope_still_inherits_denials_too(self):
        """Regression: adding approvals must not drop the existing deny
        inheritance this view already had."""
        assert "org_deny" in _INHERITED_TIERS["user"]
        assert "project_deny" in _INHERITED_TIERS["user"]

    def test_org_scope_has_no_narrower_scope_to_inherit_from(self):
        assert "org_approve" not in _INHERITED_TIERS["org"]
        assert "project_approve" not in _INHERITED_TIERS["org"]

    def test_every_inherited_tier_has_a_state_label(self):
        for scope, tiers in _INHERITED_TIERS.items():
            for tier in tiers:
                assert tier in _STATE, f"{tier} (scope={scope}) has no _STATE label"
