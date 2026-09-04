"""Stable finding identity with zero secret input. PLAN.md section 6.1.

`hash(repo, file, line)` breaks on reformatting; `hash(secret)` breaks the
hard invariant. The anchor below is the surrounding code with the match
span blanked out -- stable under reformatting, and containing not one byte
of the secret by construction.
"""

from __future__ import annotations

import hashlib
import re

_WHITESPACE_RE = re.compile(r"\s+")


def build_anchor(line_text: str, column_start: int, match_length: int) -> str:
    blanked = line_text[:column_start] + "\x00" + line_text[column_start + match_length :]
    return _WHITESPACE_RE.sub(" ", blanked).strip()


def compute_finding_id(
    repo_id: str, file_path: str, pattern_id: str, anchor: str, ordinal: int
) -> str:
    payload = "|".join((repo_id, file_path, pattern_id, anchor, str(ordinal)))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:32]
