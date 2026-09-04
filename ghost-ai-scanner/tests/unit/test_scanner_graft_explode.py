# =============================================================
# FILE: tests/unit/test_scanner_graft_explode.py
# PROJECT: PatronAI — scanner graft
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Lock the Phase 3 server-side contract for the three
#          scanner-graft finding types (declared_dependency,
#          browser_extension, hardcoded_secret) end to end through
#          explode_endpoint_findings — the same replay path
#          test_endpoint_scan_flow.py locks for the Phase 1A types:
#          - one finding -> one event, correct type/severity/provider
#          - severity escalation (browser_extension host access,
#            declared_dependency is_ai_related) actually fires
#          - _finding_signature is stable across an identical re-scan
#            and distinct across findings of the same type that only
#            differ by their key field (dependency name, extension id,
#            file+line) — the collision this phase's own review caught
#          - copy_phase_1a_fields never lets the vendored tool's own
#            "provider"/"category" field overwrite the event's
#            synthetic dedup-key fields of the same name
#          - hardcoded_secret's CRITICAL severity survives the full
#            explode, matching agent_explode._FINDING_SEVERITY
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial.
# =============================================================

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from normalizer.agent import explode_endpoint_findings  # noqa: E402

_RAW_TEMPLATE = {
    "event_type":   "ENDPOINT_SCAN",
    "device_id":    "alice-mbp",
    "device_uuid":  "11111111-2222-3333-4444-555555555555",
    "mac_primary":  "aa:bb:cc:dd:ee:ff",
    "ip_set":       ["10.0.0.7"],
    "email":        "alice@acme.com",
    "token":        "tok-abc",
    "company":      "acme",
    "timestamp":    "2026-09-04T12:00:00+00:00",
}


def _raw(*findings):
    return {**_RAW_TEMPLATE, "findings": list(findings),
            "summary": {"findings_count": len(findings)}}


def _declared_dep(**overrides):
    base = {
        "type": "declared_dependency", "repo_safe": "~/projects/repo1",
        "dependency_name": "langchain", "dependency_version": "0.3.1",
        "ecosystem": "python", "category": "llm_framework",
        "is_ai_related": True, "is_direct": True,
        "manifest_kind": "requirements.txt", "file_path": "requirements.txt",
        "line_number": 12,
    }
    base.update(overrides)
    return base


def _browser_ext(**overrides):
    base = {
        "type": "browser_extension", "extension_id": "abcdefgh",
        "name": "Grammarly", "version": "8.1.0", "browser": "Google Chrome",
        "browser_profile": "Default", "enabled": True,
        "install_origin": "web_store", "host_permissions": ["<all_urls>"],
        "permissions": ["storage"], "high_privilege_host_access": True,
    }
    base.update(overrides)
    return base


def _hardcoded_secret(**overrides):
    base = {
        "type": "hardcoded_secret", "repo_safe": "~/projects/repo1",
        "file_path": "config/settings.py", "line_number": 14,
        "secret_pattern": "aws_access_key_id", "provider": "aws",
        "confidence": "high", "blame_commit": "deadbeef",
        "blame_author": "Alice Dev", "provenance_state": "committed",
    }
    base.update(overrides)
    return base


def test_declared_dependency_becomes_one_event_with_medium_severity():
    events = explode_endpoint_findings(_raw(_declared_dep()), company="acme")
    assert len(events) == 1
    e = events[0]
    assert e["outcome"]   == "ENDPOINT_FINDING"
    assert e["category"]  == "declared_dependency"
    assert e["severity"]  == "MEDIUM"           # is_ai_related=True escalates LOW -> MEDIUM
    assert e["dependency_name"] == "langchain"
    assert e["repo_safe"] == "~/projects/repo1"


def test_declared_dependency_stays_low_when_not_ai_related():
    events = explode_endpoint_findings(
        _raw(_declared_dep(dependency_name="flask", category="web", is_ai_related=False)),
        company="acme",
    )
    assert events[0]["severity"] == "LOW"


def test_browser_extension_high_privilege_escalates_to_high():
    events = explode_endpoint_findings(_raw(_browser_ext()), company="acme")
    assert events[0]["severity"] == "HIGH"      # high_privilege_host_access=True escalates MEDIUM -> HIGH
    assert events[0]["name"]     == "Grammarly"


def test_browser_extension_without_risk_stays_medium():
    events = explode_endpoint_findings(
        _raw(_browser_ext(high_privilege_host_access=False)), company="acme",
    )
    assert events[0]["severity"] == "MEDIUM"


def test_hardcoded_secret_is_critical():
    events = explode_endpoint_findings(_raw(_hardcoded_secret()), company="acme")
    e = events[0]
    assert e["severity"] == "CRITICAL"
    assert e["file_path"] == "config/settings.py"
    assert e["blame_author"] == "Alice Dev"


def test_vendored_providers_and_categories_never_overwrite_event_dedup_keys():
    """The whole reason declared_dependency/hardcoded_secret don't
    whitelist their own "provider"/"category" fields in
    PHASE_1A_FIELD_MAP: agent_explode.py sets event["provider"] and
    event["category"] to synthetic dedup-key values BEFORE
    copy_phase_1a_fields runs. A regression here would silently corrupt
    finding_signature grouping."""
    events = explode_endpoint_findings(_raw(_hardcoded_secret()), company="acme")
    e = events[0]
    assert e["category"] == "hardcoded_secret"           # NOT "aws" or anything from the finding
    assert e["provider"] == "secret:aws:~/projects/repo1:config/settings.py:14"


def test_signature_stable_across_identical_rescan():
    """Same finding re-emitted next cycle -> same signature, so
    findings_compact can collapse repeats into one row."""
    e1 = explode_endpoint_findings(_raw(_declared_dep()), company="acme")[0]
    e2 = explode_endpoint_findings(_raw(_declared_dep()), company="acme")[0]
    assert e1["finding_signature"] == e2["finding_signature"]


def test_signature_distinct_for_different_dependencies_same_repo():
    e1 = explode_endpoint_findings(_raw(_declared_dep(dependency_name="langchain")), company="acme")[0]
    e2 = explode_endpoint_findings(_raw(_declared_dep(dependency_name="crewai")), company="acme")[0]
    assert e1["finding_signature"] != e2["finding_signature"]


def test_signature_distinct_for_same_dependency_different_repos():
    e1 = explode_endpoint_findings(_raw(_declared_dep(repo_safe="~/projects/repo1")), company="acme")[0]
    e2 = explode_endpoint_findings(_raw(_declared_dep(repo_safe="~/projects/repo2")), company="acme")[0]
    assert e1["finding_signature"] != e2["finding_signature"]


def test_signature_distinct_for_secrets_on_different_lines_same_file():
    """Two different secrets in the same file must not collapse into
    one entity — this is exactly the process_name="" collision this
    phase's review found and fixed via _provider_for()'s composite key."""
    e1 = explode_endpoint_findings(_raw(_hardcoded_secret(line_number=14)), company="acme")[0]
    e2 = explode_endpoint_findings(_raw(_hardcoded_secret(line_number=88)), company="acme")[0]
    assert e1["finding_signature"] != e2["finding_signature"]


def test_signature_distinct_for_same_extension_different_browser():
    e1 = explode_endpoint_findings(_raw(_browser_ext(browser="Google Chrome")), company="acme")[0]
    e2 = explode_endpoint_findings(_raw(_browser_ext(browser="Mozilla Firefox")), company="acme")[0]
    assert e1["finding_signature"] != e2["finding_signature"]


def test_mixed_batch_of_all_three_new_types_and_a_legacy_type():
    """Sanity check the three new types coexist in one payload alongside
    an existing category without interference."""
    events = explode_endpoint_findings(
        _raw(_declared_dep(), _browser_ext(), _hardcoded_secret(),
             {"type": "browser", "domain": "chat.openai.com"}),
        company="acme",
    )
    assert len(events) == 4
    types = {e["category"] for e in events}
    assert types == {"declared_dependency", "browser_extension", "hardcoded_secret", "browser"}
