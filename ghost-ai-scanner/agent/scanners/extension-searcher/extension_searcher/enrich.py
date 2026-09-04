"""Locale resolution and timestamp conversion.

PLAN.md section 6.4 (the `__MSG_*` localization gotcha) and section 6.5 /
6.7 (the Chromium-epoch-vs-Unix-epoch trap) live here — isolated because
both are documented as the most likely places for a silent, wrong-but-not-
crashing bug (PLAN.md section 12).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

_MSG_NAME_RE = re.compile(r"^__MSG_(.+)__$")
_CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_FALLBACK_LOCALES = ("en_US", "en")


def resolve_localized_name(
    raw_name: str,
    version_dir: Path,
    default_locale: str | None,
) -> tuple[str, tuple[str, ...]]:
    """Resolve a manifest `name` that may be a `__MSG_key__` reference.

    Returns (resolved_name, warnings). Lazily reads `_locales/*/messages.json`
    only when `raw_name` actually needs it (PLAN.md section 7, rule 7).
    """
    match = _MSG_NAME_RE.match(raw_name)
    if not match:
        return raw_name, ()

    key = match.group(1)
    locales_dir = version_dir / "_locales"
    if not locales_dir.is_dir():
        return raw_name, ("locale_unresolved",)

    candidates = [default_locale] if default_locale else []
    candidates.extend(_FALLBACK_LOCALES)

    tried: set[str] = set()
    for locale in candidates:
        if not locale or locale in tried:
            continue
        tried.add(locale)
        resolved = _read_message(locales_dir / locale / "messages.json", key)
        if resolved is not None:
            return resolved, ()

    # Last resort: the first available locale directory.
    try:
        for entry in sorted(locales_dir.iterdir()):
            if entry.name in tried or not entry.is_dir():
                continue
            resolved = _read_message(entry / "messages.json", key)
            if resolved is not None:
                return resolved, ()
    except OSError:
        pass

    return raw_name, ("locale_unresolved",)


def _read_message(messages_path: Path, key: str) -> str | None:
    if not messages_path.is_file():
        return None
    try:
        with messages_path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    entry = data.get(key) or data.get(key.lower())
    if isinstance(entry, dict):
        message = entry.get("message")
        if isinstance(message, str):
            return message
    return None


def chromium_time_to_iso(value: str | int | None) -> str | None:
    """Convert a Chromium/WebKit timestamp: microseconds since 1601-01-01 UTC.

    This is NOT Unix time (PLAN.md section 6.5 / edge case 8) — the single
    most likely silent bug in the whole tool if this converter is skipped.
    """
    if value is None:
        return None
    try:
        microseconds = int(value)
    except (TypeError, ValueError):
        return None
    if microseconds <= 0:
        return None
    try:
        return (_CHROMIUM_EPOCH + timedelta(microseconds=microseconds)).isoformat()
    except OverflowError:
        logger.warning("Chromium timestamp out of range: %r", value)
        return None


def gecko_time_to_iso(value: int | float | None) -> str | None:
    """Convert a Gecko timestamp: milliseconds since the Unix epoch."""
    if value is None:
        return None
    try:
        millis = float(value)
    except (TypeError, ValueError):
        return None
    if millis <= 0:
        return None
    try:
        return datetime.fromtimestamp(millis / 1000, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        logger.warning("Gecko timestamp out of range: %r", value)
        return None
