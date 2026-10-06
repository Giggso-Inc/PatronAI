"""Fail-open fingerprint gate so antitamper watch loops cannot re-mail.

Same finding (host + event_type + path + hashes) emits at most once per TTL.
A new hash / different event_type gets a new fingerprint and may alert again.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

_log = logging.getLogger(__name__)

# Match Hub ingest open-cause collapse window (alert_ingest.py).
DEFAULT_TTL_SEC = int(os.environ.get("ANTITAMPER_EMIT_TTL_SEC") or 3600)


def fingerprint(
    *,
    product: str,
    hostname: str,
    event_type: str,
    file_path: str,
    old_hash: str | None = None,
    new_hash: str | None = None,
) -> str:
    raw = "|".join(
        [
            (product or "").strip().lower(),
            (hostname or "").strip().lower(),
            (event_type or "").strip().upper(),
            (file_path or "").strip().replace("\\", "/"),
            (old_hash or ""),
            (new_hash or ""),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def source_event_id(product: str, fp: str) -> str:
    """Stable Hub source_event_id — identical finding → identical id → ingest duplicate."""
    return f"{product}:tamper:{fp[:32]}"


def _state_path(home: Path | None = None) -> Path:
    if home is not None:
        root = home
    else:
        env = os.environ.get("ANTITAMPER_DEDUPE_HOME") or os.environ.get(
            "PATRON_ANTITAMPER_HOME"
        ) or os.environ.get("RAVEN_ANTITAMPER_HOME")
        if env:
            root = Path(env)
        else:
            root = Path(
                os.environ.get("LOCALAPPDATA")
                or os.environ.get("XDG_DATA_HOME")
                or (Path.home() / ".local" / "share")
            ) / "antitamper-dedupe"
    root.mkdir(parents=True, exist_ok=True)
    return root / "emitted.json"


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(path: Path, data: dict) -> None:
    try:
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as e:
        _log.warning("antitamper dedupe save failed: %s", e)


def already_emitted(fp: str, *, ttl_sec: int = DEFAULT_TTL_SEC, home: Path | None = None) -> bool:
    path = _state_path(home)
    data = _load(path)
    entry = data.get(fp)
    if not entry:
        return False
    try:
        ts = float(entry.get("ts") or 0)
    except (TypeError, ValueError):
        return False
    if time.time() - ts > max(60, int(ttl_sec)):
        return False
    return True


def mark_emitted(fp: str, *, home: Path | None = None, meta: dict | None = None) -> None:
    path = _state_path(home)
    data = _load(path)
    # prune expired while writing
    now = time.time()
    keep = {
        k: v
        for k, v in data.items()
        if isinstance(v, dict) and now - float(v.get("ts") or 0) <= DEFAULT_TTL_SEC * 2
    }
    keep[fp] = {"ts": now, **(meta or {})}
    _save(path, keep)


def should_emit(fp: str, *, ttl_sec: int = DEFAULT_TTL_SEC, home: Path | None = None) -> bool:
    """True if this finding has not been Hub-emitted recently."""
    return not already_emitted(fp, ttl_sec=ttl_sec, home=home)
