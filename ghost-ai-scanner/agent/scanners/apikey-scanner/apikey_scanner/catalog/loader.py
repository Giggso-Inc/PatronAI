"""Load, validate, and compile the pattern catalog.

PLAN.md section 3.2: the catalog is DATA. This module is the only place
that reads catalog/patterns.json; adding a provider is a JSON edit, never
a code change here.

Each pattern keeps its own compiled `re.Pattern` rather than being merged
into one giant alternation: patterns declare their own internal capture
group (e.g. to strip a "aws_secret_key=" prefix from the matched secret),
and merging distinct regexes into one alternation renumbers/nests those
groups unpredictably. Scanning ~60 short, anchored patterns against one
line is negligible next to the cost of a subprocess-per-file blame call,
so this trades a theoretical single-pass optimization for a design that
cannot silently miscapture.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from re import Pattern

from apikey_scanner.catalog.validators import VALIDATORS
from apikey_scanner.errors import CatalogError
from apikey_scanner.models import Confidence, PatternSpec

# The generic entropy detector is not a regex pattern -- it has no `regex`
# field in the catalog and is handled by detect/entropy.py -- but it still
# needs a PatternSpec so its id/provider/confidence flow through the same
# Finding shape as every regex hit.
GENERIC_ENTROPY_PATTERN_ID = "generic_high_entropy"


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    spec: PatternSpec
    regex: Pattern[str]


@dataclass(frozen=True, slots=True)
class Catalog:
    version: str
    specs: dict[str, PatternSpec]
    compiled: tuple[CompiledPattern, ...]
    """Regex patterns in catalog order, high-confidence patterns first is
    not required for correctness but keeps report ordering intuitive."""

    def get(self, pattern_id: str) -> PatternSpec:
        return self.specs[pattern_id]


def _validate_validator_name(name: str | None) -> None:
    if name is not None and name not in VALIDATORS:
        raise CatalogError(f"unknown validator '{name}' referenced in catalog")


def load_catalog(path: str | None = None) -> Catalog:
    if path is not None:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    else:
        raw = json.loads(
            resources.files("apikey_scanner.catalog").joinpath("patterns.json").read_text(
                encoding="utf-8"
            )
        )

    version = raw.get("catalog_version")
    if not version:
        raise CatalogError("catalog is missing catalog_version")

    entries = raw.get("patterns")
    if not isinstance(entries, list) or not entries:
        raise CatalogError("catalog has no patterns")

    specs: dict[str, PatternSpec] = {}
    compiled: list[CompiledPattern] = []

    for entry in entries:
        pattern_id = entry.get("id")
        if not pattern_id or not isinstance(pattern_id, str):
            raise CatalogError(f"catalog entry missing string id: {entry!r}")
        if pattern_id in specs:
            raise CatalogError(f"duplicate pattern id '{pattern_id}'")

        try:
            confidence = Confidence(entry["confidence"])
        except (KeyError, ValueError) as exc:
            raise CatalogError(f"pattern '{pattern_id}' has invalid confidence") from exc

        validate = entry.get("validate")
        _validate_validator_name(validate)

        capture_group = int(entry.get("capture_group", 1))

        spec = PatternSpec(
            id=pattern_id,
            name=entry.get("name", pattern_id),
            provider=entry.get("provider", "generic"),
            kind=entry.get("kind", "unknown"),
            confidence=confidence,
            capture_group=capture_group,
            requires_identifier_proximity=bool(entry.get("requires_identifier_proximity", False)),
            validate=validate,
            references=tuple(entry.get("references", ())),
        )
        specs[pattern_id] = spec

        regex_src = entry.get("regex")
        if regex_src is not None:
            try:
                rx = re.compile(regex_src)
            except re.error as exc:
                raise CatalogError(f"pattern '{pattern_id}' has invalid regex: {exc}") from exc
            if capture_group > rx.groups:
                raise CatalogError(
                    f"pattern '{pattern_id}' declares capture_group {capture_group} "
                    f"but its regex only has {rx.groups} group(s)"
                )
            compiled.append(CompiledPattern(spec=spec, regex=rx))
        elif pattern_id != GENERIC_ENTROPY_PATTERN_ID:
            raise CatalogError(
                f"pattern '{pattern_id}' has no regex and is not the entropy sentinel"
            )

    return Catalog(version=version, specs=specs, compiled=tuple(compiled))
