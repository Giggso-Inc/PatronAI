"""Patron anti-tamper — golden-hash integrity monitor for the scanner install tree.

Cowork parity (dlp_installer/features/90_antitamper). Detection + optional
restore + fail-open Hub emit. Official upgrades call build_baseline() only;
that path must not emit tamper alerts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import shutil
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

# ghost-ai-scanner/src/antitamper/scanner.py -> ghost-ai-scanner/
_DEFAULT_ROOT = Path(__file__).resolve().parents[2]
INSTALL_ROOT = Path(os.environ.get("PATRON_INSTALL_ROOT") or _DEFAULT_ROOT)

_home = os.environ.get("PATRON_ANTITAMPER_HOME")
if _home:
    BASELINE_ROOT = Path(_home) / "baseline"
else:
    BASELINE_ROOT = Path(
        os.environ.get("LOCALAPPDATA")
        or os.environ.get("XDG_DATA_HOME")
        or (Path.home() / ".local" / "share")
    ) / "patron-antitamper" / "baseline"

INCLUDE_SUFFIX = {".py", ".ps1", ".sh", ".json"}
INCLUDE_NAMES = {"VERSION", "requirements.txt", "pyproject.toml"}
EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".venv", ".git", "tests", "test",
    "docs", "DOC", "dist", "baseline", "node_modules", ".mypy_cache",
    "alembic",  # migrations churn on deploy; not endpoint-tamper surface
}
EXCLUDE_NAMES = {
    "test-install-config.json",
}
EXCLUDE_SUFFIX = {".pyc", ".log", ".err", ".tmp", ".pid", ".processing"}


def _version() -> str:
    for candidate in (INSTALL_ROOT / "VERSION", INSTALL_ROOT.parent / "VERSION"):
        try:
            v = candidate.read_text(encoding="utf-8").strip()
            if v:
                return v
        except OSError:
            continue
    return os.environ.get("PATRON_AGENT_VERSION") or "unknown"


def _is_protected(p: Path) -> bool:
    try:
        rel = p.relative_to(INSTALL_ROOT)
    except ValueError:
        return False
    if set(rel.parts[:-1]) & EXCLUDE_DIRS:
        return False
    if p.name in EXCLUDE_NAMES or p.suffix.lower() in EXCLUDE_SUFFIX:
        return False
    return p.name in INCLUDE_NAMES or p.suffix.lower() in INCLUDE_SUFFIX


def _protected_files() -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(INSTALL_ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if _is_protected(p):
                out.append(p)
    return sorted(out)


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sign_key() -> bytes:
    tok = (
        os.environ.get("RAVEN_AGENT_KEY")
        or os.environ.get("PATRON_AGENT_TOKEN")
        or f"patron-local:{socket.gethostname()}"
    )
    return tok.encode("utf-8")


def _sign(body: str) -> str:
    return hmac.new(_sign_key(), body.encode("utf-8"), hashlib.sha256).hexdigest()


def build_baseline() -> Path:
    """Hash + copy protected files into version-stamped golden store.

    Call only from official install/upgrade. Does not emit tamper events.
    """
    d = BASELINE_ROOT / _version()
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    (d / "files").mkdir(parents=True, exist_ok=True)

    files: dict[str, dict] = {}
    for p in _protected_files():
        rel = p.relative_to(INSTALL_ROOT).as_posix()
        dest = d / "files" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        files[rel] = {"sha256": _sha256(p), "size": p.stat().st_size}

    body = json.dumps(
        {
            "version": _version(),
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files": files,
        },
        sort_keys=True,
        indent=2,
    )
    (d / "manifest.json").write_text(body, encoding="utf-8")
    (d / "manifest.sig").write_text(_sign(body), encoding="utf-8")
    return d


def load_baseline() -> tuple[Path | None, dict | None, bool]:
    d = BASELINE_ROOT / _version()
    try:
        body = (d / "manifest.json").read_text(encoding="utf-8")
        sig = (d / "manifest.sig").read_text(encoding="utf-8").strip()
    except OSError:
        return None, None, False
    try:
        manifest = json.loads(body)
    except ValueError:
        return None, None, False
    return d, manifest, hmac.compare_digest(sig, _sign(body))


def scan(manifest: dict) -> list[tuple[str, str, str | None, str | None]]:
    """Return (rel_path, event_type, old_hash, new_hash) divergences."""
    findings: list[tuple[str, str, str | None, str | None]] = []
    for rel, meta in sorted(manifest.get("files", {}).items()):
        p = INSTALL_ROOT / rel
        if not p.is_file():
            findings.append((rel, "DELETED", meta.get("sha256"), None))
            continue
        actual = _sha256(p)
        if actual != meta.get("sha256"):
            findings.append((rel, "MODIFIED", meta.get("sha256"), actual))
    known = set(manifest.get("files", {}))
    for p in _protected_files():
        rel = p.relative_to(INSTALL_ROOT).as_posix()
        if rel not in known:
            findings.append((rel, "ADDED", None, _sha256(p)))
    return findings


def restore(baseline_dir: Path, rel: str) -> bool:
    src = baseline_dir / "files" / rel
    if not src.is_file():
        return False
    try:
        dst = INSTALL_ROOT / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return True
    except OSError:
        return False


def run_once(
    *,
    restore_enabled: bool = True,
    interval_sec: int = 30,
    org: str = "",
    user_email: str = "",
    user_id: str | None = None,
    persist=True,
    emit=True,
) -> list[dict]:
    """One scan pass. Returns finding dicts. Persist/emit are fail-open."""
    baseline_dir, manifest, sig_ok = load_baseline()
    results: list[dict] = []

    if not manifest or not sig_ok:
        finding = {
            "file_path": "(baseline)",
            "event_type": "BASE_FAIL",
            "old_hash": None,
            "new_hash": None,
            "restored": False,
            "restore_ok": None,
            "hostname": socket.gethostname(),
            "agent_version": _version(),
            "baseline_version": _version(),
            "check_interval_s": interval_sec,
            "watcher_pid": os.getpid(),
            "user_email": user_email or None,
            "user_id": user_id,
            "detail": "no baseline" if not manifest else "signature mismatch",
        }
        results.append(finding)
        _handle_finding(finding, org=org, persist=persist, emit=emit)
        return results

    for rel, event_type, old_h, new_h in scan(manifest):
        do_restore = restore_enabled and event_type in {"MODIFIED", "DELETED"}
        restore_ok = restore(baseline_dir, rel) if do_restore else None
        finding = {
            "file_path": rel,
            "event_type": event_type,
            "old_hash": old_h,
            "new_hash": new_h,
            "restored": bool(do_restore),
            "restore_ok": restore_ok,
            "hostname": socket.gethostname(),
            "agent_version": _version(),
            "baseline_version": manifest.get("version") or _version(),
            "check_interval_s": interval_sec,
            "watcher_pid": os.getpid(),
            "user_email": user_email or None,
            "user_id": user_id,
        }
        results.append(finding)
        _handle_finding(finding, org=org, persist=persist, emit=emit)
    return results


def _handle_finding(finding: dict, *, org: str, persist: bool, emit: bool) -> None:
    tamper_id = None
    if persist:
        try:
            from antitamper.ledger import record_event
            tamper_id = record_event(finding, org_slug=org or None)
        except Exception as e:
            _log.warning("patron antitamper persist failed: %s", e)
    if not emit:
        return
    try:
        from antitamper.emit_dedupe import (
            fingerprint,
            mark_emitted,
            should_emit,
            source_event_id,
        )
        fp = fingerprint(
            product="patron",
            hostname=str(finding.get("hostname") or ""),
            event_type=str(finding.get("event_type") or ""),
            file_path=str(finding.get("file_path") or ""),
            old_hash=finding.get("old_hash"),
            new_hash=finding.get("new_hash"),
        )
        if not should_emit(fp):
            _log.info(
                "patron antitamper emit skipped (dedupe) path=%s type=%s",
                finding.get("file_path"), finding.get("event_type"),
            )
            return
        from notify.hub_alerts import emit_tamper
        # Stable id — Hub ingest duplicate + 60m collapse are backstops.
        eid = source_event_id("patron", fp)
        emit_tamper(
            org or "unknown",
            eid,
            detail=f"{finding['event_type']}: {finding['file_path']}",
            user=finding.get("user_email") or "",
            device=finding.get("hostname") or "",
            payload={
                "file_path": finding["file_path"],
                "event_type": finding["event_type"],
                "old_hash": finding.get("old_hash"),
                "new_hash": finding.get("new_hash"),
                "restored": finding.get("restored"),
                "restore_ok": finding.get("restore_ok"),
                "agent_version": finding.get("agent_version"),
                "tamper_id": tamper_id,
                "fingerprint": fp,
                "messaging_event": "patron_tamper",
            },
        ) and mark_emitted(
            fp, meta={"event_type": finding.get("event_type"), "path": finding.get("file_path")}
        )
    except Exception as e:
        _log.warning("patron antitamper emit failed: %s", e)


def watch_loop(*, interval_sec: int = 30, restore_enabled: bool = True, **kwargs) -> None:
    while True:
        try:
            run_once(restore_enabled=restore_enabled, interval_sec=interval_sec, **kwargs)
        except Exception as e:
            _log.warning("patron antitamper scan error: %s", e)
        time.sleep(max(5, int(interval_sec)))


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Patron anti-tamper scanner")
    ap.add_argument("--baseline", action="store_true", help="Build golden baseline (upgrade path)")
    ap.add_argument("--once", action="store_true", help="Single scan pass")
    ap.add_argument("--interval", type=int, default=30)
    ap.add_argument("--no-restore", action="store_true")
    ap.add_argument("--org", default=os.environ.get("PATRON_ORG", ""))
    ap.add_argument("--user-email", default=os.environ.get("PATRON_USER_EMAIL", ""))
    args = ap.parse_args()

    if args.baseline:
        path = build_baseline()
        print(f"baseline written: {path}")
        try:
            from antitamper.ledger import upsert_enrollment
            upsert_enrollment(
                hostname=socket.gethostname(),
                user_email=args.user_email or None,
                agent_version=_version(),
                baseline_version=_version(),
                baseline_id=str(path),
                enabled=True,
                restore=not args.no_restore,
                interval_sec=args.interval,
            )
        except Exception as e:
            _log.warning("enrollment update failed (non-fatal): %s", e)
    elif args.once:
        findings = run_once(
            restore_enabled=not args.no_restore,
            interval_sec=args.interval,
            org=args.org,
            user_email=args.user_email,
        )
        print(json.dumps(findings, indent=2))
    else:
        watch_loop(
            interval_sec=args.interval,
            restore_enabled=not args.no_restore,
            org=args.org,
            user_email=args.user_email,
        )
