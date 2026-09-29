"""Shared Hub licence read-only gate for product → Hub telemetry.

Used by Patron / CoWork / GREAAS alert emitters. Stdlib only.

Strategy: reactive only. On a real emit 403 ``LICENCE_EXPIRED``,
``note_error`` caches the block for ``_CACHE_TTL_SEC``. Happy-path emits
do **not** probe Hub first — that would double outbound HTTP on every
alert. Optional ``probe()`` remains for ops / explicit checks.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

_log = logging.getLogger(__name__)

_CACHE_TTL_SEC = 300.0
_MSG = "Org licence expired — contact admin. Hub uploads paused."

_read_only_until: float = 0.0
_logged_once: bool = False


def is_blocked() -> bool:
    """Return True while a prior LICENCE_EXPIRED response is cached."""
    return time.monotonic() < _read_only_until


def mark_expired(ttl_sec: float = _CACHE_TTL_SEC) -> None:
    """Cache a licence-expired block for ``ttl_sec`` (minimum 30s)."""
    global _read_only_until, _logged_once
    _read_only_until = time.monotonic() + max(30.0, ttl_sec)
    _logged_once = False


def clear() -> None:
    """Clear any cached licence block (e.g. after admin renew)."""
    global _read_only_until, _logged_once
    _read_only_until = 0.0
    _logged_once = False


def _parse_expired(body: str | bytes | None, status_code: int | None) -> bool:
    if status_code is not None and int(status_code) != 403:
        return False
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")
    try:
        data = json.loads(text) if text else {}
    except Exception:
        return "LICENCE_EXPIRED" in text
    if not isinstance(data, dict):
        return False
    if data.get("code") == "LICENCE_EXPIRED":
        return True
    detail = data.get("detail")
    return isinstance(detail, dict) and detail.get("code") == "LICENCE_EXPIRED"


def probe(hub_url: str, agent_key: str = "", timeout: float = 5.0) -> bool | None:
    """Optional explicit Hub licence check (not used on the emit hot path).

    Returns True (writable), False (read-only / expired), or None on error.
    """
    base = (hub_url or "").rstrip("/")
    if not base:
        return None
    req = urllib.request.Request(
        f"{base}/api/v1/licence/status",
        method="GET",
        headers={
            "Accept": "application/json",
            **({"X-Raven-Agent": agent_key} if agent_key else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except Exception as exc:
        _log.debug("licence probe failed hub=%s: %s", base, exc)
        return None
    if not isinstance(data, dict):
        return None
    if data.get("readOnly") is True:
        mark_expired()
        return False
    clear()
    return True


def should_skip(hub_url: str = "", agent_key: str = "") -> bool:
    """Return True if Hub uploads should be skipped (cached licence expired).

    Does not probe Hub on the happy path — rely on ``note_error`` after a
    real emit failure. ``hub_url`` / ``agent_key`` are accepted for API
    compatibility with call sites.
    """
    global _logged_once
    _ = (hub_url, agent_key)
    if is_blocked():
        if not _logged_once:
            _log.warning(_MSG)
            _logged_once = True
        return True
    return False


def note_error(exc: BaseException, body: bytes | str = b"") -> bool:
    """If ``exc`` is a Hub LICENCE_EXPIRED 403, cache the block and return True."""
    global _logged_once
    code = getattr(exc, "code", None)
    if code is None:
        code = getattr(exc, "status", None)
    raw = body
    if not raw:
        reader = getattr(exc, "read", None)
        if callable(reader):
            try:
                raw = reader(800)
            except Exception:
                raw = b""
    if _parse_expired(raw, int(code) if code else None):
        mark_expired()
        if not _logged_once:
            _log.warning(_MSG)
            _logged_once = True
        return True
    return False
