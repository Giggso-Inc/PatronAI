# =============================================================
# FRAGMENT: scan_declared_deps.py.frag
# PROJECT: PatronAI — scanner graft
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Adapter for the vendored AI-SDK-Scanner companion
#          (agent/scanners/ai-sdk-scanner/). Runs it once per repo in
#          DISCOVERED_REPOS (set by scan_repo_discovery), parses its
#          --format json output, and emits one `declared_dependency`
#          finding per matched AI/ML dependency it declares.
#
#          --ai-only is passed deliberately, not left at the tool's own
#          default. AI-SDK-Scanner reports every dependency by design
#          ("langchain sits next to flask" — its own README, section on
#          why there's no severity field). findings_store.write() is a
#          full read-modify-write of the day's object PER finding
#          (see src/jobs/tshark_ingest.py's docstring for the math on
#          why that matters at volume) — an unfiltered inventory from a
#          20-repo laptop would multiply that badly. --ai-only keeps
#          the endpoint payload to what PatronAI's matcher actually
#          needs a verdict on.
#
#          Optional module — a laptop without the companion installed
#          (PATRONAI_ENABLE_SCANNERS=0 at install time) returns [].
# DEPENDS: scan_repo_discovery (DISCOVERED_REPOS), scan_redactor
#          (_safe_finding, _has_unredacted_secret)
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial. Phase 2 of the scanner-graft plan.
# =============================================================

_DECLARED_DEPS_PKG_DIR   = AGENT_DIR / "scanners" / "ai_sdk_scanner"
_DECLARED_DEPS_MAX_REPOS = 25    # cap repos scanned per cycle — volume control
_DECLARED_DEPS_MAX_RECORDS_PER_REPO = 200  # cap records per repo — volume control
_DECLARED_DEPS_TIMEOUT_SECONDS = 30


def _declared_deps_python_bin() -> str:
    """Match the whole scan block's own invocation: `python` on Windows
    (no python3 binary there), `python3` everywhere else."""
    return "python" if OS_NAME == "windows" else "python3"


def _run_ai_sdk_scanner(repo_path: Path) -> list:
    """Invoke the vendored ai_sdk_scanner package against one repo.
    Returns its `records` list, or [] on any failure — a scan error in
    one repo must never abort the rest of the endpoint scan."""
    try:
        out = subprocess.check_output(
            [_declared_deps_python_bin(), "-m", "ai_sdk_scanner",
             str(repo_path), "--format", "json", "--ai-only"],
            cwd=str(_DECLARED_DEPS_PKG_DIR),
            env={**os.environ, "PYTHONPATH": str(_DECLARED_DEPS_PKG_DIR)},
            stderr=subprocess.DEVNULL, text=True, timeout=_DECLARED_DEPS_TIMEOUT_SECONDS,
        )
        envelope = json.loads(out)
        return list(envelope.get("records") or [])[:_DECLARED_DEPS_MAX_RECORDS_PER_REPO]
    except Exception:
        return []


def scan_declared_deps() -> list:
    """Declared-dependency inventory (AI-SDK-Scanner adapter). One
    `declared_dependency` finding per AI/ML dependency declared in a
    manifest across every repo in DISCOVERED_REPOS."""
    if not _DECLARED_DEPS_PKG_DIR.exists():
        return []
    out: list = []
    for repo in DISCOVERED_REPOS[:_DECLARED_DEPS_MAX_REPOS]:
        repo_path = Path(str(repo.get("path_safe", "")).replace("~", str(Path.home()), 1))
        if not repo_path.is_dir():
            continue
        for record in _run_ai_sdk_scanner(repo_path):
            finding = {
                "type":               "declared_dependency",
                "repo_safe":          repo.get("path_safe", ""),
                "dependency_name":    str(record.get("dependency_name", ""))[:120],
                "dependency_version": str(record.get("dependency_version", ""))[:60],
                "normalized_name":    str(record.get("normalized_name", ""))[:120],
                "ecosystem":          str(record.get("ecosystem", ""))[:24],
                "category":           str(record.get("category", ""))[:60],
                "is_ai_related":      bool(record.get("is_ai_related", False)),
                "is_direct":          bool(record.get("is_direct", False)),
                "manifest_kind":      str(record.get("manifest_kind", ""))[:40],
                "file_path":          str(record.get("file_path", ""))[:200],
                "line_number":        record.get("line_number"),
            }
            safe = _safe_finding(finding)
            if _has_unredacted_secret(safe):
                continue                                  # privacy gate — drop
            out.append(safe)
    return out
