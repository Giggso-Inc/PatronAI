# =============================================================
# FRAGMENT: scan_browser_extensions.py.frag
# PROJECT: PatronAI — scanner graft
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Adapter for the vendored Extension Searcher companion
#          (agent/scanners/extension-searcher/). Runs it once per
#          device, parses its --format json output, and emits one
#          `browser_extension` finding per installed extension across
#          every browser and profile on the machine.
#
#          Complements, does not replace, scan_browsers()'s history
#          check — that reads visited domains; this reads what's
#          actually installed and what it can reach. --risk tags any
#          extension with near-total host access
#          (host_permissions matching <all_urls> / *://*/*); the
#          adapter promotes that to `severity_hint: HIGH` so
#          agent_explode.py's _FINDING_SEVERITY can act on it without
#          re-deriving the permission check server-side.
#
#          --no-state skips writing Chromium's local per-profile cache
#          files — this scan is read-only, no artefact left behind.
#
#          Optional module — a laptop without the companion installed
#          (PATRONAI_ENABLE_SCANNERS=0 at install time) returns [].
# DEPENDS: scan_redactor (_safe_finding, _has_unredacted_secret)
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial. Phase 2 of the scanner-graft plan.
# =============================================================

_BROWSER_EXT_PKG_DIR = AGENT_DIR / "scanners" / "extension_searcher"
_BROWSER_EXT_MAX_RECORDS = 400   # cap records per cycle — volume control
_BROWSER_EXT_TIMEOUT_SECONDS = 30


def _browser_ext_python_bin() -> str:
    return "python" if OS_NAME == "windows" else "python3"


def scan_browser_extensions() -> list:
    """Browser extension inventory (Extension Searcher adapter). One
    `browser_extension` finding per installed extension, across every
    browser/profile Extension Searcher can enumerate on this OS."""
    if not _BROWSER_EXT_PKG_DIR.exists():
        return []
    try:
        out_raw = subprocess.check_output(
            [_browser_ext_python_bin(), "-m", "extension_searcher",
             "--format", "json", "--no-state", "--risk"],
            cwd=str(_BROWSER_EXT_PKG_DIR),
            env={**os.environ, "PYTHONPATH": str(_BROWSER_EXT_PKG_DIR)},
            stderr=subprocess.DEVNULL, text=True, timeout=_BROWSER_EXT_TIMEOUT_SECONDS,
        )
        envelope = json.loads(out_raw)
    except Exception:
        return []

    out: list = []
    for record in list(envelope.get("extensions") or [])[:_BROWSER_EXT_MAX_RECORDS]:
        warnings = record.get("warnings") or []
        finding = {
            "type":              "browser_extension",
            "extension_id":      str(record.get("extension_id", ""))[:120],
            "name":              str(record.get("name", ""))[:160],
            "version":           str(record.get("version", ""))[:40],
            "browser":           str(record.get("browser", ""))[:60],
            "browser_profile":   str(record.get("profile_name", ""))[:80],
            "enabled":           bool(record.get("enabled", False)),
            "install_origin":    str(record.get("install_origin", ""))[:40],
            "host_permissions":  [str(p)[:80] for p in (record.get("host_permissions") or [])][:20],
            "permissions":       [str(p)[:80] for p in (record.get("permissions") or [])][:20],
            "high_privilege_host_access": "high_privilege_host_access" in warnings,
        }
        safe = _safe_finding(finding)
        if _has_unredacted_secret(safe):
            continue                                  # privacy gate — drop
        out.append(safe)
    return out
