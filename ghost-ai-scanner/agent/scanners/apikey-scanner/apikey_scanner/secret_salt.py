"""Per-installation random salt for opt-in features that hash sensitive
bytes: --track-rotation (secret_fingerprint, PLAN.md section 6.2) and
--hash-authors (author identity, PLAN.md section 7.4).

The salt lives outside the findings database and is never stored in it or
exported -- leaking the DB does not help crack a fingerprint, and losing
the salt file just resets rotation-tracking/author-hash continuity, an
accepted failure mode (PLAN.md section 6.2 resolution).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
from pathlib import Path


def load_or_create_salt(salt_path: Path) -> bytes:
    if salt_path.exists():
        return salt_path.read_bytes()
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(32)
    salt_path.write_bytes(salt)
    with contextlib.suppress(OSError):
        os.chmod(salt_path, 0o600)
    return salt


def fingerprint(salt: bytes, secret: str) -> str:
    """HMAC-SHA256(salt, secret), truncated to 16 hex chars. Called only
    from detect/engine.py at the moment the candidate is already in scope
    for detection -- never re-derived from a stored value.
    """
    digest = hmac.new(salt, secret.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()
    return digest[:16]


def hash_author(salt: bytes, identity: str) -> str:
    digest = hashlib.sha256(salt + identity.encode("utf-8", errors="replace")).hexdigest()
    return digest[:16]
