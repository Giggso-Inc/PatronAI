"""Identifier proximity: is this candidate the value assigned to, or passed
as, something that sounds like a secret? PLAN.md section 4.3 step 3 -- this
is the load-bearing gate for the generic entropy detector.
"""

from __future__ import annotations

import re

_SECRET_IDENTIFIER = re.compile(
    r"(?i)(key|token|secret|password|passwd|pwd|auth|credential|"
    r"api[_-]?key|access|private|bearer|signature|salt|cert|passphrase)"
)

# candidate is the RHS of `identifier <assign-op> "candidate"` for some
# assignment-like operator across common languages.
_ASSIGNMENT_CANDIDATE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.\-]{0,60})\s*(?:[:=]{1,2}|=>)\s*[\"']?([^\s\"'`]{8,256})[\"']?"
)

# candidate passed as a string argument to call(name-like-secret, "...")
_CALL_ARG_CANDIDATE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.]{0,60})\s*\(\s*[\"']([^\"'`]{8,256})[\"']"
)


def find_context_candidates(line: str) -> list[tuple[str, int, int]]:
    """Return (candidate, start, end) for every RHS-of-assignment or
    call-argument string on the line whose identifier looks secret-ish.
    """
    results: list[tuple[str, int, int]] = []
    for match in _ASSIGNMENT_CANDIDATE.finditer(line):
        identifier, candidate = match.group(1), match.group(2)
        if _SECRET_IDENTIFIER.search(identifier):
            start = match.start(2)
            results.append((candidate, start, start + len(candidate)))
    for match in _CALL_ARG_CANDIDATE.finditer(line):
        identifier, candidate = match.group(1), match.group(2)
        if _SECRET_IDENTIFIER.search(identifier):
            start = match.start(2)
            results.append((candidate, start, start + len(candidate)))
    return results
