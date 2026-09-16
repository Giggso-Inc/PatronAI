"""Shannon entropy, charset-aware. PLAN.md section 4.3.

Entropy alone is noise -- minified JS and base64 images score just as high
as real secrets. This module only computes the number; the gating (length,
identifier proximity, filters) lives in engine.py and context.py.
"""

from __future__ import annotations

import math
import re

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_\-]+=*$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def charset_kind(candidate: str) -> str:
    if _HEX_RE.match(candidate):
        return "hex"
    if _BASE64_RE.match(candidate):
        return "base64"
    return "mixed"


def meets_entropy_threshold(
    candidate: str, *, min_entropy_hex: float, min_entropy_base64: float
) -> tuple[bool, float]:
    """Returns (passes, entropy_bits). Threshold depends on the apparent
    charset: hex has only 16 symbols so its entropy ceiling is lower than
    base64's 64-ish symbols -- a single threshold would either reject all
    real hex secrets or accept all base64 noise.
    """
    entropy = shannon_entropy(candidate)
    kind = charset_kind(candidate)
    threshold = min_entropy_hex if kind == "hex" else min_entropy_base64
    return entropy >= threshold, entropy
