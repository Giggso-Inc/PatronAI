"""Named checksum validators. PLAN.md section 3.2 -- the one permitted
exception to "catalog is data, never code": a pattern may reference a
validator by name, but adding a validator is a rare, reviewed code change.

Every function here takes only the candidate string and returns bool. None
of them log, none of them return the input, and none of them are wired up
to a network call -- validating a checksum is math on bytes already in
hand, never a request that would transmit the secret (PLAN.md section 1.3).

Deliberately absent: a GitHub/GitLab token CRC32 validator. Their real
checksum algorithm could not be verified against public specification with
enough confidence to risk silently dropping genuine leaked tokens as
"invalid" -- a false negative here is worse than no validator at all. If
one is added later it needs a citation and a recall-corpus test proving it
does not reject real-shaped tokens.
"""

from __future__ import annotations

from collections.abc import Callable


def luhn(candidate: str) -> bool:
    """Luhn mod-10 checksum, digits only. Some token/card-like identifiers
    embed a Luhn check digit; a failing checksum is strong evidence the
    string is not that identifier (e.g. a random digit run of similar shape).
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) != len(candidate) or len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def hex_even_length(candidate: str) -> bool:
    """A hex-encoded secret must have an even character count (whole
    bytes). Guards against a regex accidentally matching a truncated
    hex-like run at a word boundary.
    """
    body = candidate[2:] if candidate.lower().startswith("0x") else candidate
    return len(body) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in body)


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "luhn": luhn,
    "hex_even_length": hex_even_length,
}
