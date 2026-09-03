# =============================================================
# FILE: src/retina/normaliser.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Canonical JSON serialisation and SHA-256 computation for
#          the retina fingerprint. Produces byte-identical output
#          regardless of collection order — a required invariant so
#          that the same real-world state always produces the same hash
#          across multiple scans and across platforms.
#
# Normalisation rules (per spec):
#   - All string values lowercase (where case-insensitive)
#   - Arrays sorted lexicographically, duplicates removed
#   - Null or missing dimension replaced with empty list
#   - Keys sorted alphabetically in the JSON output
#   - No insignificant whitespace (compact separators)
#   - Schema version "v" field included for future evolution
#
# DEPENDS: hashlib, json (stdlib only)
# AUDIT LOG:
#   v1.0.0  2026-09-02  Initial. RavenHub Card — Patron side.
# =============================================================

from __future__ import annotations

import hashlib
import json
import unicodedata


_DIMS = ("d1", "d2", "d3", "d4", "d5", "d6", "d7")
_SCHEMA_VERSION = "1"


def _normalise_dim(values: list[str] | None) -> list[str]:
    """Return a sorted, deduped, NFC-normalised lowercase list.

    Unicode NFC normalisation is applied before lowercasing so that
    the same logical value (e.g. a process name with an accented char)
    produces identical bytes on macOS (NFD) and Linux (NFC). Without
    this, cross-platform hash invariance is not guaranteed.
    """
    if not values:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        norm = unicodedata.normalize("NFC", (v or "").strip()).lower()
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    out.sort()
    return out


def normalise(dimensions: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return a fully normalised copy of the dimensions dict.

    Ensures all seven dimension keys are present and each value is a sorted,
    deduped list of lowercase strings. Unknown keys are silently dropped.
    """
    return {dim: _normalise_dim(dimensions.get(dim)) for dim in _DIMS}


def canonical_json(normalised_dims: dict[str, list[str]]) -> bytes:
    """Produce the canonical JSON bytes from a normalised dimensions dict.

    The output is deterministic: sorted keys, compact separators, UTF-8
    encoded. The schema version is embedded so future format changes produce
    a different hash by construction.
    """
    payload = {"v": _SCHEMA_VERSION, **normalised_dims}
    return json.dumps(payload, sort_keys=True,
                      separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def compute_hash(normalised_dims: dict[str, list[str]]) -> str:
    """Return the 64-character lowercase hex SHA-256 retina hash."""
    return hashlib.sha256(canonical_json(normalised_dims)).hexdigest()
