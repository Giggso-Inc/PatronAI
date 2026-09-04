# =============================================================
# FILE: tests/unit/test_rule_model.py
# PROJECT: PatronAI
# VERSION: 1.1.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Pure-data tests for src/matcher/rule_model.py.
#          No AWS, no LocalStack — runs in any environment with src/ on sys.path.
# AUDIT LOG:
#   v1.0.0  2026-04-25  Initial. Group 6.
#   v1.1.0  2026-09-04  Add OUTCOMES + validate_greylist_rule tests (three-tier).
# =============================================================

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from matcher.rule_model import (  # noqa: E402
    normalize_domain, normalize_severity, is_too_broad, valid_glob,
    validate_rule, validate_allow_rule, validate_code_rule, validate_greylist_rule,
    parse_csv_text, dedupe, find_conflicts,
    OUTCOMES,
)


# ── normalize_domain ────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("https://Flowiseai.com/login", "flowiseai.com"),
    ("http://api.openai.com:443/v1", "api.openai.com"),
    ("ChatGPT.com.",                 "chatgpt.com"),
    ('"chatgpt.com"',                "chatgpt.com"),
    ("\u200bchatgpt.com",            "chatgpt.com"),
    ("  CHATGPT.COM/",               "chatgpt.com"),
    ("",                              ""),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


# ── normalize_severity ──────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("high",       "HIGH"),
    ("Medium",     "MEDIUM"),
    ("LOW ",       "LOW"),
    ("",           "HIGH"),
    ("invalid",    "HIGH"),
])
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


# ── is_too_broad ────────────────────────────────────────────────
@pytest.mark.parametrize("p", ["*", "*.com", "*.org", "*.io", "*.ai"])
def test_too_broad_blocked(p):
    assert is_too_broad(p)


@pytest.mark.parametrize("p", ["*.openai.com", "api.anthropic.com", "chatgpt.com"])
def test_too_broad_allowed(p):
    assert not is_too_broad(p)


def test_valid_glob_accepts_normal():
    assert valid_glob("*.openai.com")
    assert valid_glob("api.anthropic.com")


# ── validate_rule (network deny) ────────────────────────────────
def test_validate_rule_happy_path():
    out = validate_rule({
        "name": "OpenAI", "category": "LLM",
        "domain": " https://API.OpenAI.com/ ", "port": "443",
        "severity": "high", "notes": "",
    })
    assert out["domain"] == "api.openai.com"
    assert out["port"] == 443
    assert out["severity"] == "HIGH"


def test_validate_rule_rejects_too_broad():
    with pytest.raises(ValueError, match="too broad"):
        validate_rule({"domain": "*.com", "port": "443"})


def test_validate_rule_rejects_bad_port():
    with pytest.raises(ValueError, match="not numeric"):
        validate_rule({"domain": "x.com", "port": "abc"})


def test_validate_rule_rejects_port_oob():
    with pytest.raises(ValueError, match="out of range"):
        validate_rule({"domain": "x.com", "port": "70000"})


def test_validate_rule_rejects_both_empty():
    with pytest.raises(ValueError, match="both empty"):
        validate_rule({"domain": "", "port": ""})


# ── validate_allow_rule + validate_code_rule ────────────────────
def test_validate_allow_rule_rejects_empty():
    with pytest.raises(ValueError, match="empty"):
        validate_allow_rule({"domain_pattern": ""})


def test_validate_code_rule_lowercases_pattern():
    assert validate_code_rule({"pattern": "LangChain"})["pattern"] == "langchain"


# ── parse_csv_text ──────────────────────────────────────────────
def test_parse_csv_text_aggregates_errors():
    raw = (
        "name,category,domain,port,severity,notes\n"
        "OK,LLM,api.openai.com,443,HIGH,\n"
        "BAD,LLM,*.com,443,HIGH,too broad\n"
        "BAD2,LLM,x.com,abc,HIGH,bad port\n"
    )
    clean, errors = parse_csv_text(raw, validate_rule)
    assert len(clean) == 1
    assert len(errors) == 2
    assert errors[0]["line"] == 3
    assert "too broad" in errors[0]["reason"]


# ── dedupe ──────────────────────────────────────────────────────
def test_dedupe_last_write_wins():
    rows = [
        {"domain": "x.com", "port": 443, "severity": "HIGH"},
        {"domain": "x.com", "port": 443, "severity": "MEDIUM"},
    ]
    out = dedupe(rows, key_cols=("domain", "port"))
    assert len(out) == 1
    assert out[0]["severity"] == "MEDIUM"


# ── find_conflicts ──────────────────────────────────────────────
def test_find_conflicts_pairs_overlap():
    allow = [{"domain_pattern": "*.openai.com"}]
    deny  = [{"domain": "api.openai.com", "port": 443}]
    pairs = find_conflicts(allow, deny)
    assert len(pairs) == 1
    assert pairs[0]["allow"]["domain_pattern"] == "*.openai.com"


def test_find_conflicts_none_when_no_overlap():
    allow = [{"domain_pattern": "*.example.com"}]
    deny  = [{"domain": "api.openai.com", "port": 443}]
    assert find_conflicts(allow, deny) == []


# ── OUTCOMES constant ────────────────────────────────────────────
def test_outcomes_contains_greylist():
    assert "GREYLIST" in OUTCOMES


def test_outcomes_contains_all_expected():
    for expected in ("AUTHORIZED", "UNAUTHORIZED", "GREYLIST", "UNKNOWN"):
        assert expected in OUTCOMES


# ── validate_greylist_rule ───────────────────────────────────────
def test_validate_greylist_rule_happy_path():
    out = validate_greylist_rule({
        "name": "Perplexity AI",
        "domain_pattern": "perplexity.ai",
        "notes": "AI search — review usage",
    })
    assert out["domain_pattern"] == "perplexity.ai"
    assert out["name"] == "Perplexity AI"
    assert out["notes"] == "AI search — review usage"


def test_validate_greylist_rule_glob_pattern():
    out = validate_greylist_rule({
        "name": "Cohere API",
        "domain_pattern": "api.cohere.ai",
        "notes": "",
    })
    assert out["domain_pattern"] == "api.cohere.ai"


def test_validate_greylist_rule_rejects_empty_domain():
    with pytest.raises(ValueError, match="empty"):
        validate_greylist_rule({"name": "X", "domain_pattern": "", "notes": ""})


def test_validate_greylist_rule_rejects_too_broad():
    with pytest.raises(ValueError, match="too broad"):
        validate_greylist_rule({"name": "X", "domain_pattern": "*.ai", "notes": ""})


def test_validate_greylist_rule_rejects_bare_wildcard():
    with pytest.raises(ValueError, match="too broad"):
        validate_greylist_rule({"name": "X", "domain_pattern": "*", "notes": ""})


def test_validate_greylist_rule_normalizes_domain():
    out = validate_greylist_rule({
        "name": "Poe",
        "domain_pattern": "https://poe.com/",
        "notes": "",
    })
    assert out["domain_pattern"] == "poe.com"


# ── parse_csv_text with greylist validator ───────────────────────
def test_parse_csv_greylist_aggregates_errors():
    raw = (
        "name,domain_pattern,notes\n"
        "Perplexity AI,perplexity.ai,ok\n"
        "Too Broad,*.ai,too broad\n"
        "Empty,,no domain\n"
    )
    clean, errors = parse_csv_text(raw, validate_greylist_rule)
    assert len(clean) == 1
    assert clean[0]["domain_pattern"] == "perplexity.ai"
    assert len(errors) == 2
