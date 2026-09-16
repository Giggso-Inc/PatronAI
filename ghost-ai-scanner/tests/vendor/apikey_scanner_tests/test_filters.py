from __future__ import annotations

from apikey_scanner.detect import filters


def test_aws_doc_example_key_is_not_structurally_suppressed():
    # This is the exact planted canary in test_canary.py (PLAN.md section
    # 11.2). It contains "EXAMPLE" -- if the keyword heuristic applied to
    # structural matches, this real regression would silently reappear.
    assert filters.should_suppress_structural_match("AKIAIOSFODNN7EXAMPLE") is False


def test_aws_doc_example_key_is_suppressed_by_generic_keyword_check():
    # The full keyword heuristic (used only for the entropy detector,
    # which has no structural signal to fall back on) legitimately flags it.
    assert filters.has_placeholder_keyword("AKIAIOSFODNN7EXAMPLE") is True


def test_all_same_char_is_structurally_synthetic():
    assert filters.is_structurally_synthetic("AAAAAAAAAAAAAAAAAAAA") is True


def test_sequential_run_is_structurally_synthetic():
    assert filters.is_structurally_synthetic("abcdefghijklmnopqrst") is True


def test_real_looking_random_string_is_not_structurally_synthetic():
    assert filters.is_structurally_synthetic("aK3x9QmZ7pL2vN8sT1wY") is False


def test_env_indirection_is_suppressed():
    assert filters.is_indirection("${API_KEY}") is True
    assert filters.is_indirection("os.environ[API_KEY]") is True
    assert filters.is_indirection("os.environ.get") is True


def test_real_looking_value_is_not_indirection():
    assert filters.is_indirection("aK3x9QmZ7pL2vN8sT1wY") is False


def test_uuid_is_deliberately_not_suppressed():
    # PLAN.md section 5.2: UUIDs are NOT suppressed outright -- some real
    # credential formats (e.g. Heroku API keys) are UUID-shaped, and those
    # patterns rely on their own nearby-keyword context rather than a
    # blanket "looks like a UUID" filter.
    assert filters.is_structural_non_secret("123e4567-e89b-12d3-a456-426614174000") is False


def test_sri_hash_is_structural_non_secret():
    assert filters.is_structural_non_secret("sha256-" + "A" * 44) is True


def test_placeholder_substrings_caught_by_generic_check():
    for candidate in ("your_api_key_here", "changeme123456789012", "REDACTED_SECRET_VALUE_X"):
        assert filters.has_placeholder_keyword(candidate) is True
