"""Shared version-specifier classification. PLAN.md section 6.1.

`dependency_version` must never state something false — this module is
where "is this a pin, a range, or nothing at all?" gets decided, once,
the same way for every parser.
"""

from __future__ import annotations

import re

from ai_sdk_scanner.models import Ecosystem, VersionSpecKind

_URL_SCHEME_RE = re.compile(r"^(git\+|https?://|ssh://|file:|github:)", re.IGNORECASE)
_PYPI_EXACT_PIN_RE = re.compile(r"^==\s*[0-9A-Za-z.\-+!]+$")
_NPM_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$")
_NPM_RANGE_HINT_RE = re.compile(r"[\^~<>*x]|\bx\b|\|\||\s-\s")
_PLAIN_VERSION_RE = re.compile(r"^\d+(\.\d+)*([.\-][0-9A-Za-z]+)*$")
_MAVEN_DYNAMIC_RE = re.compile(r"[+\[\](),]")


def find_line_number(text_lines: list[str], package_name: str) -> int | None:
    """Best-effort 1-based line number of `package_name` in a structured file.

    TOML and JSON parsers discard position information, so for those
    formats the line is located by scanning the raw text for the name as a
    key or list item. This is explicitly best-effort: it returns the FIRST
    plausible match and None when nothing matches, which is why
    `ScanRecord.line_number` is documented as approximate for structured
    formats and exact only for line-oriented ones like requirements.txt.
    """
    if not package_name:
        return None
    needle = re.escape(package_name.lower())
    # The name must be followed by something that ends the identifier: a
    # closing quote, a version operator, an extras bracket, a marker
    # semicolon, whitespace, or end-of-line. Without this, PEP 621's
    # `"openai>=1.0"` form never matched, because the name and its
    # specifier share one quoted string.
    boundary = r"""(?=["'\s\]=<>!~;,\[]|$)"""
    patterns = (
        re.compile(rf"""["']{needle}{boundary}"""),  # quoted key or list item
        re.compile(rf"^{needle}\s*="),                # bare TOML key
        re.compile(rf"^-\s+{needle}{boundary}"),      # YAML list item
    )
    for i, line in enumerate(text_lines, start=1):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith("#"):
            continue
        if any(pattern.search(stripped) for pattern in patterns):
            return i
    return None


def classify_version_spec(version_spec: str, ecosystem: Ecosystem) -> VersionSpecKind:
    """Classify a raw, as-declared version string. Never resolves or guesses
    an actual version — only says what KIND of specifier this is."""
    spec = version_spec.strip()

    if not spec or spec in ("*", "latest", "any"):
        return VersionSpecKind.UNPINNED

    if _URL_SCHEME_RE.match(spec) or "://" in spec or spec.startswith("@"):
        return VersionSpecKind.URL

    if ecosystem == Ecosystem.PYPI:
        if "," in spec:
            return VersionSpecKind.RANGE
        if _PYPI_EXACT_PIN_RE.match(spec):
            return VersionSpecKind.PINNED
        return VersionSpecKind.RANGE

    if ecosystem == Ecosystem.NPM:
        if spec.startswith("workspace:"):
            return VersionSpecKind.UNPINNED
        if _NPM_EXACT_SEMVER_RE.match(spec):
            return VersionSpecKind.PINNED
        if _NPM_RANGE_HINT_RE.search(spec):
            return VersionSpecKind.RANGE
        return VersionSpecKind.RANGE

    if ecosystem == Ecosystem.GO:
        # go.mod has no range operator at all -- every entry is a concrete
        # module version (or a pseudo-version like v0.0.0-2021...-abc123f),
        # which Minimal Version Selection treats as a floor but which the
        # file itself always states as one specific version.
        return VersionSpecKind.PINNED

    if ecosystem == Ecosystem.MAVEN:
        if spec.startswith("${") or spec in ("LATEST", "RELEASE"):
            # `${jackson.version}`-style property placeholders are genuinely
            # unresolvable from one file — Maven's property inheritance
            # spans parent POMs this parser does not follow (see module
            # docstring). UNPINNED is the honest answer: "not stated here",
            # not a guess at what it resolves to.
            return VersionSpecKind.UNPINNED
        if _MAVEN_DYNAMIC_RE.search(spec):
            # Range brackets [1.0,2.0), or Gradle's dynamic "1.+" / "+".
            return VersionSpecKind.RANGE
        if _PLAIN_VERSION_RE.match(spec):
            # Maven/Gradle, unlike Poetry or Cargo: a bare version with no
            # operator IS an exact pin, not an implicit caret range.
            return VersionSpecKind.PINNED
        return VersionSpecKind.RANGE

    if ecosystem == Ecosystem.CARGO:
        if spec.startswith("="):
            return VersionSpecKind.PINNED
        # Cargo's own docs: an operator-less version is a caret requirement
        # by default (same convention as Poetry) -- NOT an exact pin.
        return VersionSpecKind.RANGE

    if ecosystem == Ecosystem.NUGET:
        if spec.startswith("[") and spec.endswith("]") and "," not in spec:
            return VersionSpecKind.PINNED  # NuGet's explicit exact form: [1.2.3]
        if _MAVEN_DYNAMIC_RE.search(spec):
            return VersionSpecKind.RANGE  # bracket/parenthesis range syntax
        # NuGet spec: a bare version means ">= that version", a minimum,
        # not an exact pin -- classifying it PINNED would overclaim.
        return VersionSpecKind.RANGE

    if ecosystem == Ecosystem.RUBYGEMS:
        if spec.startswith("~>") or re.search(r"[<>]", spec) or "," in spec:
            return VersionSpecKind.RANGE
        # RubyGems: an operator-less requirement means "=" (exact) by
        # convention -- the opposite default from Cargo/Poetry above.
        return VersionSpecKind.PINNED

    if ecosystem == Ecosystem.COMPOSER:
        if _PLAIN_VERSION_RE.match(spec):
            # Composer, like Maven: bare version is exact, no implicit caret.
            return VersionSpecKind.PINNED
        return VersionSpecKind.RANGE

    return VersionSpecKind.RANGE
