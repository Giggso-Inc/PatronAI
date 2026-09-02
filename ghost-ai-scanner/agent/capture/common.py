# =============================================================
# FILE: agent/capture/common.py
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Shared plumbing for the capture companion - paths, config,
#          code-integrity verification, atomic writes, directory sizing.
#          Imported by capture_service.py (boot) and sync_task.py (hourly).
# DEPENDS: stdlib ONLY. No pip packages, ever - see the note below.
# =============================================================
"""Shared plumbing for the capture companion.

STDLIB ONLY, DELIBERATELY. The scan agent needs one pip package (bcrypt) and
carries a whole fallback ladder for it: try system pip, hit PEP 668's
externally-managed-environment block on any current distro, fall back to
building a private venv. Its own comment records that the earlier
unconditional `pip3 install` "aborted the installer on every current distro".

The companion avoids that entire class of failure by needing nothing. Keep it
that way: use urllib.request over `requests`, hashlib over any crypto package.

Self-test:  python common.py
"""
import hashlib
import json
import os
import platform
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────
# Service-owned, NOT user-writable. The keylog under here is a master key to
# every TLS session on the machine, so this tree must be locked down by the
# installer (SYSTEM/root only) - see install/ scripts.
_DATA_DIRS = {
    "Windows": Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "PatronAI" / "capture",
    "Darwin":  Path("/Library/Application Support/PatronAI/capture"),
    "Linux":   Path("/var/lib/patronai/capture"),
}


def data_dir() -> Path:
    """Root of the companion's on-disk state for this OS."""
    override = os.environ.get("PATRONAI_CAPTURE_DIR")
    if override:
        return Path(override)
    try:
        return _DATA_DIRS[platform.system()]
    except KeyError:
        raise SystemExit(f"Unsupported platform: {platform.system()}")


def paths() -> dict:
    """Every directory the companion uses. Callers should not build paths."""
    root = data_dir()
    return {
        "root":    root,
        "keylog":  root / "keylog",
        "capture": root / "capture",   # transient .etl/.pcapng
        "spool":   root / "spool",     # gzipped JSONL awaiting upload
        "state":   root / "state",
        "logs":    root / "logs",
    }


def ensure_dirs() -> dict:
    p = paths()
    for key, path in p.items():
        path.mkdir(parents=True, exist_ok=True)
    return p


# ── Config ───────────────────────────────────────────────────────────────
# Written by the installer. `urls.json` is the presigned-URL bundle the
# existing agent already re-mints every 24h; the companion reads the same file
# rather than inventing a second credential path.

# Both files are written by the INSTALLER, which on Windows is PowerShell.
# Windows PowerShell 5.1's `Set-Content -Encoding utf8` emits a UTF-8 BOM
# (EF BB BF), and Python's plain "utf-8" decoder rejects it with
# "Unexpected UTF-8 BOM". utf-8-sig strips a BOM when present and is a no-op
# when absent, so it is correct for a file we did not write ourselves.
# (agent_store.get_object_text carries the same note for .ps1 files - the
# lesson was already learned in this repo, just not applied here.)
_CONFIG_ENCODING = "utf-8-sig"


def load_config() -> dict:
    """Read config.json (token, device id, company) written at install time."""
    f = paths()["state"] / "config.json"
    if not f.exists():
        raise SystemExit(f"Not configured: {f} is missing. Re-run the installer.")
    try:
        return json.loads(f.read_text(encoding=_CONFIG_ENCODING))
    except ValueError as exc:
        raise SystemExit(f"{f} is not valid JSON: {exc}")


def load_urls() -> dict:
    """Read the presigned-URL bundle. Empty dict only when genuinely ABSENT.

    A malformed bundle raises rather than returning {}. Swallowing the parse
    error made a corrupt file indistinguishable from a missing key: a BOM in
    urls.json surfaced as "no code_manifest_url in urls.json", which sent the
    reader looking at the minting code instead of the file encoding.
    """
    f = paths()["state"] / "urls.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding=_CONFIG_ENCODING))
    except ValueError as exc:
        raise SystemExit(f"{f} is not valid JSON: {exc}")
    except OSError as exc:
        raise SystemExit(f"cannot read {f}: {exc}")


# ── Code integrity ───────────────────────────────────────────────────────
# We do NOT auto-update code. We verify it has not been modified since
# install, and refuse to run if it has.
#
# The manifest is fetched from S3 rather than read from disk on purpose:
# whoever can modify a .py on this machine can equally modify a manifest
# sitting next to it, so a local manifest proves nothing.
#
# Be honest about the limit: this detects accidental or casual modification.
# It is NOT a defence against a local administrator, who can also point the
# fetch elsewhere. Integrity assurance, not tamper-proofing.

OK, MISMATCH, UNAVAILABLE = "OK", "MISMATCH", "UNAVAILABLE"

# Files covered by the manifest. Anything executable that the companion runs
# belongs here; a file not listed is a file nobody is checking.
VERIFIED_FILES = ["pktmon_to_jsonl.py", "common.py",
                  "capture_service.py", "sync_task.py", "uploader.py"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def local_manifest(code_dir: Path = None) -> dict:
    """{filename: sha256} for every VERIFIED_FILES entry present on disk."""
    code_dir = code_dir or Path(__file__).resolve().parent
    out = {}
    for name in VERIFIED_FILES:
        f = code_dir / name
        if f.exists():
            out[name] = sha256_file(f)
    return out


def compare_manifests(expected: dict, actual: dict) -> list:
    """Return a list of human-readable differences. Empty list == match.

    Reports three distinct failures, because they mean different things:
    a changed file (tampering or a partial update), a missing file (broken
    install), and an unexpected extra file the manifest does not cover.
    """
    problems = []
    for name, want in sorted(expected.items()):
        got = actual.get(name)
        if got is None:
            problems.append(f"{name}: MISSING on disk")
        elif got != want:
            # ASCII only: this string is printed by a Windows service whose
            # console is cp1252, where a non-ASCII char raises
            # UnicodeEncodeError - the integrity failure would then crash
            # while reporting itself instead of naming the modified file.
            problems.append(f"{name}: MODIFIED (expected {want[:12]}..., got {got[:12]}...)")
    for name in sorted(set(actual) - set(expected)):
        problems.append(f"{name}: present on disk but not in the manifest")
    return problems


def verify_integrity(code_dir: Path = None, timeout: int = 20):
    """(status, detail) - status is OK / MISMATCH / UNAVAILABLE.

    UNAVAILABLE means we could not obtain the server-side manifest at all
    (no URL configured, or the fetch failed). It is deliberately distinct
    from MISMATCH so the caller can treat "cannot verify" differently from
    "verification failed" - they are not the same risk.
    """
    url = load_urls().get("code_manifest_url", "")
    if not url:
        return UNAVAILABLE, "no code_manifest_url in urls.json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            expected = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError) as exc:
        return UNAVAILABLE, f"manifest fetch failed: {exc}"

    problems = compare_manifests(expected, local_manifest(code_dir))
    if problems:
        return MISMATCH, "; ".join(problems)
    return OK, f"{len(expected)} files verified"


def require_integrity(logger=print, allow_unverified: bool = None) -> None:
    """Gate an entry point on code integrity. Exits non-zero on MISMATCH.

    Refusing to run rather than warning-and-continuing is deliberate, and
    matches the installer's own no-admin behaviour: a capture agent that
    reports healthy while running unverified code is the failure mode worth
    avoiding most.

    `allow_unverified` (env: PATRONAI_ALLOW_UNVERIFIED=1) exists ONLY so the
    companion is deployable before the server-side manifest endpoint lands.
    It must not be set in production.
    """
    if allow_unverified is None:
        allow_unverified = os.environ.get("PATRONAI_ALLOW_UNVERIFIED") == "1"

    status, detail = verify_integrity()
    if status == OK:
        logger(f"integrity: OK - {detail}")
        return
    if status == MISMATCH:
        raise SystemExit(f"integrity: REFUSING TO RUN - code modified since install: {detail}")
    if allow_unverified:
        logger(f"integrity: UNVERIFIED ({detail}) - continuing, "
               "PATRONAI_ALLOW_UNVERIFIED=1 is set. Do not use this in production.")
        return
    raise SystemExit(f"integrity: REFUSING TO RUN - cannot verify code: {detail}")


# ── Disk helpers ─────────────────────────────────────────────────────────

def dir_size(path: Path) -> int:
    """Total bytes of regular files under `path`. 0 when absent."""
    if not path.exists():
        return 0
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def write_atomic(target: Path, data: bytes) -> None:
    """Write via a temp file in the SAME directory, then rename.

    Same-directory matters: os.replace is only atomic within one filesystem,
    and the system temp dir is frequently a different one. A file must never
    appear in the spool until it is complete, or the uploader will ship a
    truncated archive.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read_counter(name: str) -> int:
    f = paths()["state"] / name
    try:
        return int(f.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def write_counter(name: str, value: int) -> None:
    write_atomic(paths()["state"] / name, str(value).encode("utf-8"))


def _selftest():
    import shutil
    tmp = Path(tempfile.mkdtemp(prefix="patronai-capture-selftest-"))
    os.environ["PATRONAI_CAPTURE_DIR"] = str(tmp)
    try:
        p = ensure_dirs()
        assert p["spool"].exists() and p["state"].exists(), p

        # Atomic write lands the final name and leaves no .tmp behind.
        target = p["spool"] / "x.jsonl.gz"
        write_atomic(target, b"payload")
        assert target.read_bytes() == b"payload"
        assert not list(p["spool"].glob("*.tmp")), list(p["spool"].iterdir())

        # dir_size counts real bytes.
        assert dir_size(p["spool"]) == len(b"payload"), dir_size(p["spool"])
        assert dir_size(p["root"] / "nope") == 0

        # Counters survive a round trip and default to 0 when absent.
        assert read_counter("seq") == 0
        write_counter("seq", 42)
        assert read_counter("seq") == 42

        # Hashing + manifest comparison.
        code = tmp / "code"
        code.mkdir()
        (code / "common.py").write_text("a", encoding="utf-8")
        (code / "sync_task.py").write_text("b", encoding="utf-8")
        actual = local_manifest(code)
        assert set(actual) == {"common.py", "sync_task.py"}, actual
        assert compare_manifests(actual, actual) == [], "identical must compare clean"

        # A modified file is reported as MODIFIED, not MISSING.
        tampered = dict(actual, **{"common.py": "0" * 64})
        problems = compare_manifests(tampered, actual)
        assert len(problems) == 1 and "MODIFIED" in problems[0], problems

        # A deleted file is reported as MISSING.
        missing = compare_manifests(actual, {"common.py": actual["common.py"]})
        assert any("MISSING" in x and "sync_task.py" in x for x in missing), missing

        # An unexpected extra file is reported too - a manifest that silently
        # ignores unknown code is not verifying much.
        extra = compare_manifests({"common.py": actual["common.py"]}, actual)
        assert any("not in the manifest" in x for x in extra), extra

        # A UTF-8 BOM must not break parsing. Windows PowerShell 5.1 writes
        # one with `Set-Content -Encoding utf8`, and plain utf-8 rejects it -
        # which made urls.json unreadable and surfaced as a MISSING KEY.
        # bytes.fromhex, not a "\xef..." literal - this file is read and
        # rewritten by tooling, and an escape that survives one round trip may
        # not survive the next. The hex form cannot be mangled.
        (p["state"] / "urls.json").write_bytes(
            bytes.fromhex("efbbbf")
            + b'{"code_manifest_url":"http://x","capture_post":{"url":"http://y"}}')
        got = load_urls()
        assert got.get("code_manifest_url") == "http://x", f"BOM broke urls.json parsing: {got}"

        # Malformed JSON must RAISE, not masquerade as an empty bundle.
        (p["state"] / "urls.json").write_text("{not json", encoding="utf-8")
        try:
            load_urls()
            raise AssertionError("malformed urls.json must raise, not return {}")
        except SystemExit:
            pass
        (p["state"] / "urls.json").unlink()
        assert load_urls() == {}, "a genuinely absent bundle is still {}"

        # No manifest URL configured -> UNAVAILABLE, never a false OK.
        status, detail = verify_integrity(code)
        assert status == UNAVAILABLE, (status, detail)

        print("common self-test: PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    _selftest()
