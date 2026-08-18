# =============================================================
# FILE: tests/unit/test_ravenhub_shadow_by_tool.py
# VERSION: 1.2.0
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
#   v1.1.0  2026-08-18  _endpoints_scanned coverage tests, added with
#                       workforce_total/endpoints_scanned so the card can
#                       drop its last cross-service (Raven) call.
#   v1.2.0  2026-08-18  PR#29 review M2/M3: _workforce_total coverage
#                       (incl. an assertion that the count query is
#                       org-scoped, which fails against the pre-review
#                       unscoped query) and the three route-level tests
#                       mirroring get_inventory_overview's.
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


# ── coverage / denominator (v1.1.0) ───────────────────────────────────────────

def test_endpoints_scanned_counts_distinct_devices():
    """The honest coverage figure. PatronAI only sees machines its agent is on,
    so a low shadow-AI percentage may mean "few people use it" OR "we barely
    looked" — this is what lets a reader tell those apart."""
    from routers.ravenhub import _endpoints_scanned
    events = [
        _ev(device_uuid="dev-1"),
        _ev(device_uuid="dev-1"),          # same machine, many findings
        _ev(device_uuid="dev-2"),
    ]
    assert _endpoints_scanned(events) == 2


def test_endpoints_scanned_falls_back_to_hostname():
    """Mirrors _asset_key's preference order — a finding without device_uuid is
    still a real endpoint and must not be dropped from coverage."""
    from routers.ravenhub import _endpoints_scanned
    events = [_ev(src_hostname="laptop-a"), _ev(device_uuid="dev-1")]
    assert _endpoints_scanned(events) == 2


def test_endpoints_scanned_ignores_rows_with_no_device():
    """A row identifying no machine must not become one phantom endpoint,
    which would overstate coverage — the opposite of this field's purpose."""
    from routers.ravenhub import _endpoints_scanned
    assert _endpoints_scanned([_ev(device_uuid="", src_hostname="")]) == 0
    assert _endpoints_scanned([]) == 0


# ── _workforce_total (v1.2.0 — review M1/M2) ──────────────────────────────────
# Mirrors the _db_is_admin fake-session pattern in test_ravenhub.py:207-252.

class _FakeScalar:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value

    def scalar_one_or_none(self):
        return self._value


class _FakeCountSession:
    """Session stand-in that records what the count query was filtered by, so a
    test can prove the query is org-scoped rather than counting the table."""
    def __init__(self, count):
        self._count = count
        self.executed = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, statement=None, *_a, **_kw):
        self.executed += 1
        self.last_statement = statement
        return _FakeScalar(self._count)


def _patch_identity(monkeypatch, org_id):
    """Stub get_identity, which _workforce_total imports inside the function."""
    import db.policy_queries as pq
    monkeypatch.setattr(pq, "get_identity",
                        lambda s, email: (object() if org_id else None, org_id, []))


def test_workforce_total_none_without_database_url(monkeypatch):
    from routers.ravenhub import _workforce_total
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert _workforce_total("a@giggso.com") is None


def test_workforce_total_counts_for_the_callers_org(monkeypatch):
    """Review M1: the count MUST be filtered by the caller's org. This DB is
    multi-org, so an unfiltered COUNT returns another tenant's headcount and
    silently corrupts the percentage.

    Asserts the compiled SQL actually carries the predicate — a fake that just
    returns a number would pass with or without the WHERE clause, which is
    exactly the bug being fixed.
    """
    from routers.ravenhub import _workforce_total
    import db.engine as engine_mod
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    _patch_identity(monkeypatch, "org-a")
    session = _FakeCountSession(26)
    monkeypatch.setattr(engine_mod, "get_session", lambda: session)

    assert _workforce_total("admin@giggso.com") == 26
    sql = str(session.last_statement).lower()
    assert "count(" in sql
    assert "where" in sql and "org_id" in sql, (
        f"count query is not org-scoped: {sql}")


def test_workforce_total_none_when_caller_is_not_a_policy_db_user(monkeypatch):
    """Review M1: an unknown caller has no org, so there is no denominator to
    give. None (not 0) — otherwise the card renders "N of 0 people"."""
    from routers.ravenhub import _workforce_total
    import db.engine as engine_mod
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    _patch_identity(monkeypatch, None)
    monkeypatch.setattr(engine_mod, "get_session", lambda: _FakeCountSession(999))
    assert _workforce_total("stranger@example.com") is None


def test_workforce_total_none_on_db_exception(monkeypatch):
    """A DB outage degrades to "not available", never to a fabricated 0."""
    from routers.ravenhub import _workforce_total
    import db.engine as engine_mod
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")

    def _boom():
        raise RuntimeError("connection refused")
    monkeypatch.setattr(engine_mod, "get_session", _boom)
    assert _workforce_total("a@giggso.com") is None


# ── route handler (v1.2.0 — review M3) ────────────────────────────────────────
# Mirrors get_inventory_overview's route tests (test_ravenhub.py:428-461).

def test_shadow_by_tool_non_admin_returns_200_with_no_data(monkeypatch):
    import routers.ravenhub as rh
    monkeypatch.setattr(rh, "_resolve_is_admin", lambda email: False)
    result = rh.get_shadow_by_tool(email="dev@giggso.com")
    assert isinstance(result, rh.ShadowByToolResponse)
    assert result.is_admin is False
    assert result.message == "Not an admin — no shadow AI data available."
    assert result.categories is None
    assert result.workforce_total is None


def test_shadow_by_tool_unknown_email_returns_200_not_403(monkeypatch):
    """A privilege boundary, not an authentication failure — same contract as
    /inventory/overview."""
    from fastapi import HTTPException
    import routers.ravenhub as rh

    def _deny(email):
        raise HTTPException(status_code=403, detail="Access denied")
    monkeypatch.setattr(rh, "_resolve_is_admin", _deny)
    result = rh.get_shadow_by_tool(email="totally-unknown@giggso.com")
    assert result.is_admin is False
    assert result.categories is None


def test_shadow_by_tool_admin_wires_every_field(monkeypatch):
    """Pins the merged response — **_shadow_by_tool(events) plus the two
    separately-computed fields — so a refactor cannot silently drop one."""
    import routers.ravenhub as rh
    monkeypatch.setattr(rh, "_resolve_is_admin", lambda email: True)
    monkeypatch.setattr(rh, "_blob_store", lambda: object())
    monkeypatch.setattr(rh, "_workforce_total", lambda email: 26)
    fake_events = [
        _ev(provider="mcp:claude_desktop:weather", category="mcp_server",
            device_uuid="dev-1", owner="a@x.com", email="a@x.com"),
        _ev(provider="vdb:chroma:Chroma", category="vector_db",
            device_uuid="dev-2", owner="b@x.com", email="b@x.com"),
    ]
    monkeypatch.setattr(
        rh, "_load_events",
        lambda store, email, is_admin: (fake_events, {}, {}, "2026-08-17"))

    result = rh.get_shadow_by_tool(email="admin@giggso.com")
    assert result.is_admin is True
    assert result.message is None
    assert result.source_date == "2026-08-17"
    assert result.total_tools == 2
    assert result.total_users == 2
    assert result.workforce_total == 26
    assert result.endpoints_scanned == 2
    by_cat = {c["category"]: c for c in result.categories}
    assert by_cat["MCPs"]["tools_count"] == 1
    assert by_cat["Vector DB"]["tools_count"] == 1
