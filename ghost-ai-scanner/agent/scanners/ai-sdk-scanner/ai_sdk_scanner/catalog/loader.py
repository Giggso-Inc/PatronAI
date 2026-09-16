"""Load, validate, and match against the AI-library catalog.

PLAN.md section 5: the catalog is DATA, never code. Adding a newly-released
AI SDK is a one-line edit to ai_libraries.json, never a code change.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from ai_sdk_scanner.errors import CatalogError
from ai_sdk_scanner.models import Category, Ecosystem
from ai_sdk_scanner.normalize import (
    normalize_cargo_name,
    normalize_composer_name,
    normalize_go_name,
    normalize_npm_name,
    normalize_nuget_name,
    normalize_pypi_name,
    normalize_rubygems_name,
)

_NORMALIZERS = {
    Ecosystem.PYPI: normalize_pypi_name,
    Ecosystem.NPM: normalize_npm_name,
    Ecosystem.GO: normalize_go_name,
    Ecosystem.CARGO: normalize_cargo_name,
    Ecosystem.NUGET: normalize_nuget_name,
    Ecosystem.RUBYGEMS: normalize_rubygems_name,
    Ecosystem.COMPOSER: normalize_composer_name,
    # MAVEN is deliberately absent: a Maven/Gradle coordinate is already
    # "groupId:artifactId" by the time it reaches here (built by
    # normalize_maven_name in the parser, since it needs two input
    # fields) -- this dispatch only lowercases what's left.
}

logger = logging.getLogger(__name__)

_DEFAULT_CATALOG = "ai_libraries.json"


@dataclass(frozen=True, slots=True)
class MatchResult:
    """A successful catalog match: what it is, and why it matched."""

    category: Category
    match_rule: str  # e.g. "exact:openai" or "namespace:langchain-"


@dataclass(frozen=True, slots=True)
class _NamespaceRule:
    pattern: str
    ecosystem: Ecosystem
    category: Category


@dataclass(frozen=True, slots=True)
class Catalog:
    """A loaded, validated, ready-to-match catalog."""

    version: int
    exact: dict[tuple[Ecosystem, str], Category]
    namespaces: tuple[_NamespaceRule, ...]

    def match(self, name: str, ecosystem: Ecosystem) -> MatchResult | None:
        """Normalize `name` for `ecosystem` and check exact, then namespace rules."""
        normalized = normalize_for(name, ecosystem)

        category = self.exact.get((ecosystem, normalized))
        if category is not None:
            return MatchResult(category=category, match_rule=f"exact:{normalized}")

        for rule in self.namespaces:
            if rule.ecosystem != ecosystem:
                continue
            if normalized.startswith(normalize_for(rule.pattern, ecosystem)):
                return MatchResult(category=rule.category, match_rule=f"namespace:{rule.pattern}")

        return None


def normalize_for(name: str, ecosystem: Ecosystem) -> str:
    """The canonical match key for `name` in `ecosystem`.

    Public because it is also the value surfaced as
    `ScanRecord.normalized_name` — consumers should group and dedupe on
    the same key the catalog matched with, not on the manifest's raw
    spelling.
    """
    normalizer = _NORMALIZERS.get(ecosystem)
    if normalizer is not None:
        return normalizer(name)
    # MAVEN: already "groupid:artifactid" (see _NORMALIZERS comment above).
    return name.strip().lower()


def load_catalog(path: Path | None = None) -> Catalog:
    """Load the catalog from `path`, or the packaged default.

    Raises CatalogError on anything structurally wrong — an invalid
    catalog makes every match result untrustworthy, so this must not fail
    silently (PLAN.md section 12, "catalog integrity test").
    """
    if path is not None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogError(f"Could not read catalog at {path}: {exc}") from exc
    else:
        try:
            raw = resources.files("ai_sdk_scanner.catalog").joinpath(_DEFAULT_CATALOG).read_text(
                encoding="utf-8"
            )
        except (OSError, FileNotFoundError, ModuleNotFoundError) as exc:
            raise CatalogError(f"Could not load packaged catalog: {exc}") from exc
        data = json.loads(raw)

    return _validate_and_build(data)


def _validate_and_build(data: dict[str, Any]) -> Catalog:
    if "version" not in data or not isinstance(data["version"], int):
        raise CatalogError("Catalog missing integer 'version' field")
    if "libraries" not in data or not isinstance(data["libraries"], list):
        raise CatalogError("Catalog missing 'libraries' list")

    exact: dict[tuple[Ecosystem, str], Category] = {}
    seen: set[tuple[Ecosystem, str]] = set()

    for entry in data["libraries"]:
        name = entry.get("name")
        ecosystem_raw = entry.get("ecosystem")
        category_raw = entry.get("category")
        if not name or not ecosystem_raw or not category_raw:
            raise CatalogError(f"Catalog entry missing required field: {entry!r}")

        try:
            ecosystem = Ecosystem(ecosystem_raw)
        except ValueError as exc:
            raise CatalogError(f"Unknown ecosystem {ecosystem_raw!r} in entry: {entry!r}") from exc
        try:
            category = Category(category_raw)
        except ValueError as exc:
            raise CatalogError(f"Unknown category {category_raw!r} in entry: {entry!r}") from exc

        normalized = normalize_for(name, ecosystem)
        key = (ecosystem, normalized)
        if key in seen:
            raise CatalogError(f"Duplicate catalog entry for {ecosystem.value}:{normalized}")
        seen.add(key)
        exact[key] = category

        for alias in entry.get("aliases", []):
            alias_key = (ecosystem, normalize_for(alias, ecosystem))
            if alias_key in seen:
                raise CatalogError(f"Duplicate catalog alias for {ecosystem.value}:{alias}")
            seen.add(alias_key)
            exact[alias_key] = category

    namespaces: list[_NamespaceRule] = []
    for entry in data.get("namespaces", []):
        pattern = entry.get("pattern")
        ecosystem_raw = entry.get("ecosystem")
        category_raw = entry.get("category")
        if not pattern or not pattern.strip():
            raise CatalogError(f"Namespace rule has empty pattern: {entry!r}")
        if not ecosystem_raw or not category_raw:
            raise CatalogError(f"Namespace rule missing required field: {entry!r}")
        try:
            ecosystem = Ecosystem(ecosystem_raw)
            category = Category(category_raw)
        except ValueError as exc:
            raise CatalogError(f"Invalid namespace rule: {entry!r}") from exc
        namespaces.append(_NamespaceRule(pattern=pattern, ecosystem=ecosystem, category=category))

    return Catalog(version=data["version"], exact=exact, namespaces=tuple(namespaces))
