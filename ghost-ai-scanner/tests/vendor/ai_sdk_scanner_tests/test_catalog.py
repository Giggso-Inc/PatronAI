"""Catalog loading, matching, and the section 5.4 exclusion regression
suite — this locks the boto3/requests/numpy exclusions against a
well-meaning future edit that adds them back."""

from __future__ import annotations

import json

import pytest

from ai_sdk_scanner.catalog.loader import load_catalog
from ai_sdk_scanner.errors import CatalogError
from ai_sdk_scanner.models import Category, Ecosystem


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


def test_exact_match_pypi(catalog):
    result = catalog.match("openai", Ecosystem.PYPI)
    assert result is not None
    assert result.category == Category.LLM_SDK
    assert result.match_rule == "exact:openai"


def test_exact_match_is_case_and_separator_insensitive(catalog):
    result = catalog.match("Sentence_Transformers", Ecosystem.PYPI)
    assert result is not None
    assert result.category == Category.NLP_TRANSFORMERS


def test_namespace_match_langchain_pypi(catalog):
    result = catalog.match("langchain-community", Ecosystem.PYPI)
    assert result is not None
    assert result.category == Category.AGENT_FRAMEWORK
    assert result.match_rule.startswith("namespace:")


def test_namespace_match_langchain_npm_scope(catalog):
    result = catalog.match("@langchain/core", Ecosystem.NPM)
    assert result is not None
    assert result.category == Category.AGENT_FRAMEWORK


def test_no_match_for_unrelated_package(catalog):
    assert catalog.match("express", Ecosystem.NPM) is None
    assert catalog.match("flask", Ecosystem.PYPI) is None


# --- Coverage regressions -----------------------------------------------
# A namespace rule like "langchain-" catches langchain-community but NOT
# the bare root package. That gap silently produced zero matches for the
# single most common AI framework on PyPI until a live scan exposed it,
# so the root packages are pinned here by name.

@pytest.mark.parametrize("name", [
    "langchain", "langgraph", "llama-index", "openai", "anthropic",
    "transformers", "torch", "spacy", "gliner", "bitsandbytes", "dspy",
    "mcp", "openai-agents", "litellm", "chromadb", "faiss-cpu",
])
def test_core_pypi_packages_are_catalogued(catalog, name):
    assert catalog.match(name, Ecosystem.PYPI) is not None, f"{name} must match"


@pytest.mark.parametrize("name", [
    "openai", "@anthropic-ai/sdk", "@langchain/core", "ai",
    "@modelcontextprotocol/sdk", "@aws-sdk/client-bedrock-runtime",
])
def test_core_npm_packages_are_catalogued(catalog, name):
    assert catalog.match(name, Ecosystem.NPM) is not None, f"{name} must match"


@pytest.mark.parametrize("name,ecosystem", [
    ("com.openai:openai-java", "maven"),
    ("github.com/sashabaranov/go-openai", "go"),
    ("async-openai", "cargo"),
    ("OpenAI", "nuget"),
    ("ruby-openai", "rubygems"),
    ("openai-php/client", "composer"),
])
def test_new_ecosystem_seed_entries_are_catalogued(catalog, name, ecosystem):
    assert catalog.match(name, Ecosystem(ecosystem)) is not None, f"{name} ({ecosystem}) must match"


def test_maven_namespace_catches_langchain4j_modules(catalog):
    result = catalog.match("dev.langchain4j:langchain4j-open-ai", Ecosystem.MAVEN)
    assert result is not None
    assert result.category == Category.AGENT_FRAMEWORK


def test_maven_case_insensitive_via_generic_fallback(catalog):
    # Maven has no dedicated normalizer (see catalog/loader.py's
    # _NORMALIZERS comment) -- confirms the generic lowercase fallback
    # still makes matching case-insensitive.
    assert catalog.match("COM.OPENAI:OPENAI-JAVA", Ecosystem.MAVEN) is not None


def test_cargo_hyphen_underscore_folding(catalog):
    # crates.io treats - and _ as equivalent, same as PyPI.
    assert catalog.match("async_openai", Ecosystem.CARGO) is not None


def test_bedrock_specific_client_is_catalogued_though_boto3_is_not(catalog):
    # The distinction is the whole point of the exclusion list: a
    # Bedrock-only client DOES imply AI usage; the generic AWS SDK does not.
    assert catalog.match("@aws-sdk/client-bedrock-runtime", Ecosystem.NPM) is not None
    assert catalog.match("boto3", Ecosystem.PYPI) is None


def test_ecosystem_is_not_crossed(catalog):
    # A pypi-only entry must not match on npm and vice versa.
    assert catalog.match("scikit-learn", Ecosystem.NPM) is None


# --- The named regression: PLAN.md section 5.4 ------------------------------

@pytest.mark.parametrize(
    "name", ["boto3", "requests", "httpx", "numpy", "pandas", "scipy", "pillow"]
)
def test_excluded_packages_never_match(catalog, name):
    assert catalog.match(name, Ecosystem.PYPI) is None


def test_excluded_list_is_documented_in_catalog_file():
    from importlib import resources

    raw = resources.files("ai_sdk_scanner.catalog").joinpath("ai_libraries.json").read_text(
        encoding="utf-8"
    )
    data = json.loads(raw)
    excluded_names = {e["name"] for e in data.get("excluded", [])}
    assert "boto3" in excluded_names
    assert all(e.get("reason") for e in data["excluded"]), "every exclusion must state why"


# --- Validation -------------------------------------------------------------

def test_duplicate_entry_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "version": 1,
        "libraries": [
            {"name": "openai", "ecosystem": "pypi", "category": "llm_sdk"},
            {"name": "OpenAI", "ecosystem": "pypi", "category": "llm_sdk"},
        ],
    }))
    with pytest.raises(CatalogError):
        load_catalog(bad)


def test_missing_field_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": 1, "libraries": [{"name": "openai"}]}))
    with pytest.raises(CatalogError):
        load_catalog(bad)


def test_unknown_category_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "version": 1,
        "libraries": [{"name": "openai", "ecosystem": "pypi", "category": "malware"}],
    }))
    with pytest.raises(CatalogError):
        load_catalog(bad)


def test_empty_namespace_pattern_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "version": 1,
        "libraries": [],
        "namespaces": [{"pattern": "", "ecosystem": "pypi", "category": "llm_sdk"}],
    }))
    with pytest.raises(CatalogError):
        load_catalog(bad)


def test_malformed_json_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    with pytest.raises(CatalogError):
        load_catalog(bad)
