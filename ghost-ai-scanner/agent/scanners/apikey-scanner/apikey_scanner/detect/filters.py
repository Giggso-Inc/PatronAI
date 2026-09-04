"""False-positive suppression. PLAN.md section 5.2-5.3.

Every predicate here is PURE: candidate in, bool out. No logging import
exists in this module and none may be added -- that is what keeps a
placeholder-checking function from becoming a leak path (section 5.3).
"""

from __future__ import annotations

import re

_PLACEHOLDER_SUBSTRINGS = (
    "your_", "<your", "example", "changeme", "change_me", "placeholder",
    "dummy", "sample", "redacted", "insert_", "todo", "fixme",
    "xxxxxxxx", "00000000", "12345678", "abcdefgh",
)

_INDIRECTION_RE = re.compile(
    r"^\$\{.*\}$|^\{\{.*\}\}$|^%s$|^%\(.*\)s$"
)

_INDIRECTION_CALL_RE = re.compile(
    r"(?i)^(os\.environ|process\.env|env\.get|getenv|system\.getenv|"
    r"config\.get|settings\.|vault\.|secrets_manager\.)"
)

_SRI_HASH_RE = re.compile(r"^sha(256|384|512)-[A-Za-z0-9+/=]+$")

_DATA_URI_RE = re.compile(r"^data:[a-zA-Z0-9/+.\-]+;base64,")


def has_placeholder_keyword(candidate: str) -> bool:
    """Substring/keyword heuristic ("your_", "example", "changeme", ...).

    Deliberately NOT applied to high/medium-confidence structural matches
    (engine.py): AWS's own documentation example key
    `AKIAIOSFODNN7EXAMPLE` -- the exact canary this project's own test
    suite plants (PLAN.md section 11.2) -- contains "example" and would be
    silently swallowed by this heuristic. Real leaked keys are routinely
    assigned to variables named `test_api_key` or containing "example" in
    a comment on the same line; a structural match (unique prefix/checksum)
    is strong enough evidence on its own that keyword-sniffing the value
    would only produce false negatives, never a useful true negative.
    This heuristic is reserved for the generic high-entropy detector,
    where there is no structural signal to fall back on.
    """
    lowered = candidate.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_SUBSTRINGS)


def is_structurally_synthetic(candidate: str) -> bool:
    """All-same-char or strictly sequential runs -- these are synthetic
    regardless of confidence level (no real key generator produces
    `AKIAAAAAAAAAAAAAAAAA` or `AKIA0123456789ABCDEF`), so this check is
    safe to apply even to high-confidence structural matches.
    """
    return _is_all_same_char(candidate) or _is_sequential(candidate)


def is_placeholder(candidate: str) -> bool:
    """Full placeholder check: structural + keyword. Used only by the
    generic entropy detector (engine.py) -- see has_placeholder_keyword.
    """
    return is_structurally_synthetic(candidate) or has_placeholder_keyword(candidate)


def _is_all_same_char(candidate: str) -> bool:
    stripped = candidate.strip("-_")
    return len(stripped) > 3 and len(set(stripped.lower())) == 1


def _is_sequential(candidate: str) -> bool:
    """abcdef... or 123456... run, case-insensitive, allowing wraparound."""
    if len(candidate) < 6:
        return False
    lowered = candidate.lower()
    ascending = all(
        (ord(lowered[i + 1]) - ord(lowered[i])) % 256 == 1 for i in range(len(lowered) - 1)
    )
    return ascending


def is_indirection(candidate: str) -> bool:
    return bool(_INDIRECTION_RE.match(candidate)) or bool(
        _INDIRECTION_CALL_RE.match(candidate)
    )


def is_structural_non_secret(candidate: str) -> bool:
    """SRI hashes and data URIs are never secrets, by format.

    UUIDs are deliberately NOT suppressed here (PLAN.md section 5.2): a
    UUID-shaped string is exactly what several real credential formats
    look like (Heroku API keys, some OAuth client secrets), and the
    patterns that match them already require nearby context (e.g.
    `heroku_api_key`'s regex only fires within 20 chars of the word
    "heroku"). Suppressing every UUID-shaped string here would silently
    defeat those patterns' own context anchor. A generic, contextless
    UUID sighting is reported as its own low-confidence finding rather
    than blocked outright.
    """
    return bool(_SRI_HASH_RE.match(candidate)) or bool(_DATA_URI_RE.match(candidate))


def should_suppress_structural_match(candidate: str) -> bool:
    """Used for high/medium-confidence regex matches (engine.py): structural
    placeholder shapes, indirection, and known non-secret formats -- but
    NOT the keyword/substring heuristic (see has_placeholder_keyword).
    """
    return (
        is_structurally_synthetic(candidate)
        or is_indirection(candidate)
        or is_structural_non_secret(candidate)
    )


def should_suppress_generic_match(candidate: str) -> bool:
    """Used for the generic high-entropy detector (engine.py), which has
    no structural signal and so needs every heuristic available.
    """
    return (
        is_placeholder(candidate)
        or is_indirection(candidate)
        or is_structural_non_secret(candidate)
    )
