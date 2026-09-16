# =============================================================
# FILE: tests/unit/test_ai_inventory_data.py
# PROJECT: PatronAI — Phase 1A
# VERSION: 1.0.0
# UPDATED: 2026-04-26
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock the Manager AI Inventory data helpers — pure-data slice
#          (filter / dedup / KPI counts / owner enumeration). Streamlit-
#          free; no UI dependencies.
# AUDIT LOG:
#   v1.0.0  2026-04-26  Initial. Phase 1A.
#   v1.1.0  2026-09-09  Cover apply_filters() reaching `name`/`file_path`
#                       for the three scanner-graft categories.
#   v1.2.0  2026-09-09  Cover phase_1a_only() dropping non-AI-related
#                       declared_dependency rows.
# =============================================================

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dashboard"))

from ui.manager_tab_ai_inventory_data import (   # noqa: E402
    PHASE_1A_CATEGORIES, CATEGORY_LABELS,
    phase_1a_only, dedup_latest, apply_filters, kpi_counts, owners_in,
)


def _ev(category="mcp_server", email="alice@x.com", host="alice-mbp",
        provider="mcp:claude_desktop:filesystem", severity="HIGH",
        ts="2026-04-26T12:00:00+00:00") -> dict:
    return {
        "category":     category,
        "email":        email,
        "src_hostname": host,
        "provider":     provider,
        "severity":     severity,
        "timestamp":    ts,
    }


def test_phase_1a_categories_constants_match():
    assert "mcp_server" in PHASE_1A_CATEGORIES
    assert "agent_workflow" in PHASE_1A_CATEGORIES
    assert "vector_db" in PHASE_1A_CATEGORIES
    assert "browser" not in PHASE_1A_CATEGORIES                  # legacy excluded


def test_phase_1a_only_filters_legacy_out():
    events = [_ev(category="mcp_server"), _ev(category="browser")]
    out = phase_1a_only(events)
    assert len(out) == 1
    assert out[0]["category"] == "mcp_server"


def test_phase_1a_only_drops_non_ai_declared_dependency():
    ai_dep  = dict(_ev(category="declared_dependency"), is_ai_related=True)
    non_ai  = dict(_ev(category="declared_dependency"), is_ai_related=False)
    out = phase_1a_only([ai_dep, non_ai])
    assert len(out) == 1
    assert out[0]["is_ai_related"] is True


def test_phase_1a_only_drops_declared_dependency_missing_flag():
    """No is_ai_related key at all (older/malformed event) must not leak
    through — treat missing the same as False, not True."""
    no_flag = _ev(category="declared_dependency")
    assert phase_1a_only([no_flag]) == []


def test_phase_1a_only_untouched_for_other_categories():
    """The is_ai_related filter is declared_dependency-specific — it must
    not affect any other Phase 1A category."""
    events = [_ev(category="mcp_server"), _ev(category="hardcoded_secret"),
              _ev(category="browser_extension")]
    out = phase_1a_only(events)
    assert len(out) == 3


def test_dedup_keeps_latest_per_group():
    older = _ev(ts="2026-04-25T00:00:00+00:00")
    newer = _ev(ts="2026-04-26T12:00:00+00:00")
    out = dedup_latest([older, newer])
    assert len(out) == 1
    assert out[0]["timestamp"] == newer["timestamp"]


def test_dedup_separates_by_provider():
    a = _ev(provider="mcp:claude_desktop:filesystem")
    b = _ev(provider="mcp:cursor:filesystem")
    out = dedup_latest([a, b])
    assert len(out) == 2


def test_dedup_separates_by_device():
    a = _ev(host="alice-mbp")
    b = _ev(host="alice-laptop")
    out = dedup_latest([a, b])
    assert len(out) == 2


def test_dedup_returns_newest_first():
    a = _ev(ts="2026-04-20T00:00:00+00:00",
            provider="p1")
    b = _ev(ts="2026-04-26T00:00:00+00:00",
            provider="p2")
    out = dedup_latest([a, b])
    assert out[0]["provider"] == "p2"
    assert out[1]["provider"] == "p1"


def test_apply_filters_severity():
    e1 = _ev(severity="HIGH"); e2 = _ev(severity="LOW")
    out = apply_filters([e1, e2], sev=["HIGH"], cats=[], owner="", search="")
    assert len(out) == 1 and out[0]["severity"] == "HIGH"


def test_apply_filters_category():
    a = _ev(category="mcp_server"); b = _ev(category="vector_db")
    out = apply_filters([a, b], sev=[], cats=["vector_db"],
                        owner="", search="")
    assert len(out) == 1 and out[0]["category"] == "vector_db"


def test_apply_filters_owner():
    a = _ev(email="alice@x.com"); b = _ev(email="bob@x.com")
    out = apply_filters([a, b], sev=[], cats=[],
                        owner="alice@x.com", search="")
    assert len(out) == 1 and out[0]["email"] == "alice@x.com"


def test_apply_filters_owner_all_passes_through():
    a = _ev(email="alice@x.com"); b = _ev(email="bob@x.com")
    out = apply_filters([a, b], sev=[], cats=[],
                        owner="(all)", search="")
    assert len(out) == 2


def test_apply_filters_search_matches_provider():
    a = _ev(provider="mcp:claude_desktop:filesystem")
    b = _ev(provider="vdb:chroma:chroma.sqlite3")
    out = apply_filters([a, b], sev=[], cats=[],
                        owner="", search="chroma")
    assert len(out) == 1 and "chroma" in out[0]["provider"]


def test_apply_filters_search_matches_hostname():
    a = _ev(host="alice-mbp"); b = _ev(host="bob-laptop")
    out = apply_filters([a, b], sev=[], cats=[], owner="", search="alice")
    assert len(out) == 1


def test_apply_filters_search_matches_extension_name():
    a = dict(_ev(category="browser_extension",
                provider="ext:Google Chrome:fcoeoabg"), name="Grammarly")
    b = dict(_ev(category="browser_extension",
                provider="ext:Google Chrome:aabbcc"), name="AdBlock")
    out = apply_filters([a, b], sev=[], cats=[], owner="", search="grammarly")
    assert len(out) == 1 and out[0]["name"] == "Grammarly"


def test_apply_filters_search_matches_file_path():
    a = dict(_ev(category="hardcoded_secret", provider="secret:aws:repo:x"),
             file_path="src/config/settings.py")
    b = dict(_ev(category="hardcoded_secret", provider="secret:aws:repo:y"),
             file_path="scripts/deploy.sh")
    out = apply_filters([a, b], sev=[], cats=[], owner="", search="settings.py")
    assert len(out) == 1 and out[0]["file_path"] == "src/config/settings.py"


def test_kpi_counts_counts_by_category():
    rows = [_ev(category="mcp_server"), _ev(category="mcp_server"),
            _ev(category="vector_db")]
    counts = kpi_counts(rows)
    assert counts["mcp_server"] == 2
    assert counts["vector_db"]  == 1


def test_owners_in_returns_distinct_sorted():
    rows = [_ev(email="bob@x.com"), _ev(email="alice@x.com"),
            _ev(email="alice@x.com")]
    out = owners_in(rows)
    assert out == ["alice@x.com", "bob@x.com"]


def test_category_labels_complete():
    """Every category in PHASE_1A_CATEGORIES must have a human label."""
    for c in PHASE_1A_CATEGORIES:
        assert c in CATEGORY_LABELS, f"Missing label for category {c}"
