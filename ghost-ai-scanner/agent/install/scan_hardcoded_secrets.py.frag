# =============================================================
# FRAGMENT: scan_hardcoded_secrets.py.frag
# PROJECT: PatronAI — scanner graft
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Adapter for the vendored apikey-scanner companion
#          (agent/scanners/apikey-scanner/). Runs it once per scan
#          cycle against every repo in DISCOVERED_REPOS and emits one
#          `hardcoded_secret` finding per detection metadata row —
#          repo, file, line, pattern, git provenance. Same hard
#          invariant as upstream: the secret VALUE is never read out
#          of apikey-scanner's output by this adapter, because
#          apikey-scanner's own Finding model has no field for it —
#          see apikey_scanner/models.py's module docstring.
#
#          Ephemeral by design. apikey-scanner's own README calls its
#          findings.db "a precise map an attacker would want" even
#          though it stores no secret bytes — one copy on a dev's own
#          machine is a considered trade; a populated copy shipped
#          into this repo, or left behind on hundreds of fleet laptops,
#          is not (see agent/scanners/README.md). `scan` and `report`
#          both run against a throwaway tempfile database that is
#          deleted the moment this function returns — nothing named
#          .apikey-scanner/ is ever left on disk by this adapter.
#
#          Optional module — a laptop without the companion installed
#          (PATRONAI_ENABLE_SCANNERS=0 at install time) returns [].
# DEPENDS: scan_repo_discovery (DISCOVERED_REPOS), scan_redactor
#          (_safe_finding, _has_unredacted_secret)
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial. Phase 2 of the scanner-graft plan.
# =============================================================

import tempfile

_HARDCODED_SECRETS_PKG_DIR   = AGENT_DIR / "scanners" / "apikey_scanner"
_HARDCODED_SECRETS_MAX_REPOS = 25    # cap repos scanned per cycle — volume control
_HARDCODED_SECRETS_MAX_RECORDS = 300  # cap records per cycle — volume control
_HARDCODED_SECRETS_TIMEOUT_SECONDS = 45


def _hardcoded_secrets_python_bin() -> str:
    return "python" if OS_NAME == "windows" else "python3"


def scan_hardcoded_secrets() -> list:
    """Hardcoded-secret detection (apikey-scanner adapter). One
    `hardcoded_secret` finding per detection — never the secret bytes
    themselves, only where it is and what git says about it."""
    if not _HARDCODED_SECRETS_PKG_DIR.exists():
        return []
    repo_paths = []
    for repo in DISCOVERED_REPOS[:_HARDCODED_SECRETS_MAX_REPOS]:
        repo_path = Path(str(repo.get("path_safe", "")).replace("~", str(Path.home()), 1))
        if repo_path.is_dir():
            repo_paths.append(repo_path)
    if not repo_paths:
        return []

    py = _hardcoded_secrets_python_bin()
    env = {**os.environ, "PYTHONPATH": str(_HARDCODED_SECRETS_PKG_DIR)}
    cwd = str(_HARDCODED_SECRETS_PKG_DIR)

    try:
        with tempfile.TemporaryDirectory(prefix="patronai_apikey_") as tmp:
            db_path = str(Path(tmp) / "findings.db")
            scan_cmd = [py, "-m", "apikey_scanner", "scan", "--db", db_path]
            for rp in repo_paths:
                scan_cmd += ["--root", str(rp)]
            subprocess.check_output(
                scan_cmd, cwd=cwd, env=env,
                stderr=subprocess.DEVNULL, text=True,
                timeout=_HARDCODED_SECRETS_TIMEOUT_SECONDS,
            )
            report_raw = subprocess.check_output(
                [py, "-m", "apikey_scanner", "report", "--db", db_path, "--format", "jsonl"],
                cwd=cwd, env=env, stderr=subprocess.DEVNULL, text=True,
                timeout=_HARDCODED_SECRETS_TIMEOUT_SECONDS,
            )
    except Exception:
        return []

    # repo_path -> path_safe, so the redacted form ships, never the real one.
    _safe_by_repo = {str(Path(str(r.get("path_safe", "")).replace("~", str(Path.home()), 1))): r.get("path_safe", "")
                      for r in DISCOVERED_REPOS[:_HARDCODED_SECRETS_MAX_REPOS]}

    out: list = []
    for line in report_raw.splitlines()[:_HARDCODED_SECRETS_MAX_RECORDS]:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        finding = {
            "type":            "hardcoded_secret",
            "repo_safe":       _safe_by_repo.get(record.get("repo_path", ""), ""),
            "file_path":       str(record.get("file_path", ""))[:200],
            "line_number":     record.get("line_number"),
            "secret_pattern":  str(record.get("matched_pattern_type", ""))[:80],
            "provider":        str(record.get("provider", ""))[:60],
            "confidence":      str(record.get("confidence", ""))[:20],
            "blame_commit":    str(record.get("commit_sha") or "")[:40],
            "blame_author":    str(record.get("author_name") or "")[:120],
            "provenance_state": str(record.get("provenance_state", ""))[:24],
        }
        safe = _safe_finding(finding)
        if _has_unredacted_secret(safe):
            continue                                  # privacy gate — drop
        out.append(safe)
    return out
