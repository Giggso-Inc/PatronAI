"""PLAN.md section 10: normalization must make both sides of a catalog
match agree, or matches silently fail."""

from __future__ import annotations

from ai_sdk_scanner.normalize import (
    normalize_npm_name,
    normalize_pypi_name,
    split_environment_marker,
    split_pep508_name_and_specifier,
    strip_extras,
)


def test_pypi_normalization_collapses_separators():
    assert normalize_pypi_name("Sentence_Transformers") == "sentence-transformers"
    assert normalize_pypi_name("sentence.transformers") == "sentence-transformers"
    assert normalize_pypi_name("sentence-transformers") == "sentence-transformers"
    assert normalize_pypi_name("Sentence__Transformers") == "sentence-transformers"


def test_npm_normalization_preserves_scope():
    assert normalize_npm_name("@Anthropic-AI/SDK") == "@anthropic-ai/sdk"
    assert normalize_npm_name("OpenAI") == "openai"


def test_strip_extras():
    assert strip_extras("langchain[all]") == ("langchain", ("all",))
    assert strip_extras("langchain[all, extra]") == ("langchain", ("all", "extra"))
    assert strip_extras("langchain") == ("langchain", ())


def test_split_environment_marker():
    assert split_environment_marker('openai; python_version >= "3.9"') == (
        "openai", 'python_version >= "3.9"'
    )
    assert split_environment_marker("openai") == ("openai", None)


def test_split_pep508_ordinary_specifier():
    assert split_pep508_name_and_specifier("openai>=1.0,<2") == ("openai", ">=1.0,<2")
    assert split_pep508_name_and_specifier("openai") == ("openai", "")


def test_split_pep508_direct_url():
    name, spec = split_pep508_name_and_specifier(
        "openai @ git+https://github.com/openai/openai-python@abc123"
    )
    assert name == "openai"
    assert spec == "git+https://github.com/openai/openai-python@abc123"
