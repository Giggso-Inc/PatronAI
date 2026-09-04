"""Name normalization. PLAN.md section 10.

Matching the catalog requires normalizing both sides identically, or
matches silently fail — this is the single module both `catalog/loader.py`
and every parser depend on for that.
"""

from __future__ import annotations

import re

_PYPI_SEPARATOR_RE = re.compile(r"[-_.]+")
_EXTRAS_RE = re.compile(r"^(?P<name>[^\[]+)\[(?P<extras>[^\]]*)\]$")
_DIRECT_URL_RE = re.compile(r"^([A-Za-z0-9._\-]+)\s*@\s*(.+)$")
_SPECIFIER_START_RE = re.compile(r"[=<>!~]")


def normalize_pypi_name(name: str) -> str:
    """PEP 503: lowercase, collapse runs of -, _, . to a single -.

    `Sentence_Transformers` and `sentence.transformers` and
    `sentence-transformers` must all normalize to the same string, because
    PyPI treats them as the same package and real manifests use all three
    spellings.
    """
    return _PYPI_SEPARATOR_RE.sub("-", name.strip()).lower()


def normalize_npm_name(name: str) -> str:
    """Lowercase; preserve the `@scope/name` shape exactly."""
    return name.strip().lower()


def normalize_go_name(module_path: str) -> str:
    """Lowercase a Go module path (`github.com/org/repo`).

    Go import paths are technically case-sensitive per spec, so this is a
    deliberate simplification for catalog matching, not a spec-accurate
    normalization — collision risk is negligible for known SDK paths in
    practice, and every other ecosystem here makes the same trade-off.
    """
    return module_path.strip().lower()


def normalize_cargo_name(name: str) -> str:
    """crates.io treats `-` and `_` as equivalent in a crate name — the
    same PEP-503-style folding PyPI does, documented crates.io behavior."""
    return _PYPI_SEPARATOR_RE.sub("-", name.strip()).lower()


def normalize_nuget_name(name: str) -> str:
    """NuGet package IDs are case-insensitive on nuget.org."""
    return name.strip().lower()


def normalize_rubygems_name(name: str) -> str:
    """Lowercase. Real gem names are conventionally lowercase-hyphenated
    already; this only guards against a manifest spelling one differently."""
    return name.strip().lower()


def normalize_composer_name(name: str) -> str:
    """`vendor/package`, lowercased — Packagist normalizes names this way."""
    return name.strip().lower()


def strip_extras(name: str) -> tuple[str, tuple[str, ...]]:
    """`langchain[all]` -> ("langchain", ("all",)). No brackets -> unchanged."""
    match = _EXTRAS_RE.match(name.strip())
    if not match:
        return name.strip(), ()
    base = match.group("name").strip()
    extras_raw = match.group("extras").strip()
    extras = tuple(e.strip() for e in extras_raw.split(",") if e.strip())
    return base, extras


def split_pep508_name_and_specifier(req_part: str) -> tuple[str, str]:
    """Split a PEP 508 requirement (marker and comment already stripped)
    into (name, raw version specifier). Shared by the requirements.txt
    parser and the pyproject.toml PEP 621 / PDM / uv parsing paths so the
    same grammar is applied everywhere it appears.

    Handles direct references (`name @ url`) and ordinary specifiers
    (`name>=1.0,<2`). Returns an empty specifier string for a bare name.
    """
    direct_url_match = _DIRECT_URL_RE.match(req_part)
    if direct_url_match:
        return direct_url_match.group(1).strip(), direct_url_match.group(2).strip()

    spec_start = _SPECIFIER_START_RE.search(req_part)
    if spec_start:
        name = req_part[: spec_start.start()].strip()
        version_spec = req_part[spec_start.start():].strip()
    else:
        name = req_part.strip()
        version_spec = ""
    return name, version_spec


def split_version_constraints(version_spec: str) -> tuple[str, ...]:
    """Decompose a comma-separated specifier into its individual clauses.

    `">=1.0,<2"` -> `(">=1.0", "<2")`. A single clause returns a 1-tuple;
    an empty or URL-shaped spec returns an empty tuple, since neither is a
    set of version constraints.
    """
    spec = version_spec.strip()
    if not spec or "://" in spec or spec.startswith(("git+", "file:", "github:")):
        return ()
    return tuple(part.strip() for part in spec.split(",") if part.strip())


def split_vcs_url(version_spec: str) -> tuple[str | None, str | None]:
    """Split a VCS reference into (url, ref).

    `git+https://github.com/o/r@abc123` -> (`git+https://github.com/o/r`,
    `abc123`). Returns (None, None) when the spec is not a VCS/URL
    reference. The `@ref` suffix is only split on the LAST `@` that
    follows the scheme, so `git@host:org/repo` style URLs are not
    mangled, and an `#egg=` fragment is kept out of the ref.
    """
    spec = version_spec.strip()
    if not spec:
        return None, None
    is_url = "://" in spec or spec.startswith(("git+", "file:", "github:"))
    if not is_url:
        return None, None

    fragment_free = spec.split("#", 1)[0]

    # Only consider an '@' that appears after the scheme separator.
    scheme_end = fragment_free.find("://")
    search_from = scheme_end + 3 if scheme_end != -1 else 0
    at_index = fragment_free.rfind("@", search_from)

    if at_index == -1 or at_index <= search_from:
        return spec, None
    url = fragment_free[:at_index]
    ref = fragment_free[at_index + 1:]
    return (url, ref) if ref else (spec, None)


def split_environment_marker(requirement_line: str) -> tuple[str, str | None]:
    """Split `openai; python_version >= "3.9"` into (`openai`, marker).

    Returns (requirement_part, None) when there is no marker.
    """
    if ";" not in requirement_line:
        return requirement_line.strip(), None
    req_part, _, marker_part = requirement_line.partition(";")
    return req_part.strip(), marker_part.strip() or None
