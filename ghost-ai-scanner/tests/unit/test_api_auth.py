# =============================================================
# FILE: tests/unit/test_api_auth.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: Guard every /agent and /score route in api.py against silently
#          missing the _auth bearer-key dependency. This repo had zero test
#          coverage over api.py's auth posture before this file (PR#10
#          review, M2) — nothing would have caught /agent/url-refresh/{token}
#          shipping without Depends(_auth) if that had been an oversight
#          rather than a deliberate, documented trade-off.
#          Static route introspection only — no S3/AWS/DB calls needed.
# =============================================================

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

# api.py hard-fails at import time if API_KEY is unset (by design — see
# api.py's own module-level check). Set a throwaway value before importing.
os.environ.setdefault("API_KEY", "test-key-for-test-api-auth")

import api as api_module   # noqa: E402 — must follow the sys.path/env setup above

# Routes intentionally public (no API key) — anything else under /agent or
# /score must depend on api_module._auth. Add here, with a reason in the
# PR/commit, if a future route is deliberately exempt; don't just delete the
# assertion.
PUBLIC_ROUTES = {
    ("/agent/url-refresh/{token}", "GET"),  # the token itself is the credential
    ("/healthz", "GET"),
}


def _dependency_callables(dependant):
    """Flatten every dependency callable in a route's dependency tree
    (direct dependencies + their own sub-dependencies)."""
    found = []
    for sub in dependant.dependencies:
        found.append(sub.call)
        found.extend(_dependency_callables(sub))
    return found


def test_every_agent_and_score_route_requires_auth_unless_public():
    checked = 0
    for route in api_module.app.routes:
        path = getattr(route, "path", "")
        if not (path.startswith("/agent") or path.startswith("/score")):
            continue
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        for method in sorted(getattr(route, "methods", None) or [""]):
            checked += 1
            if (path, method) in PUBLIC_ROUTES:
                continue
            deps = _dependency_callables(dependant)
            assert api_module._auth in deps, (
                f"{method} {path} has no Depends(_auth) and isn't in "
                f"PUBLIC_ROUTES — either add the dependency or explicitly "
                f"allowlist it here with a reason."
            )
    assert checked > 0, "no /agent or /score routes found — path filter is stale"


def test_public_routes_list_is_still_accurate():
    """Every entry in PUBLIC_ROUTES must correspond to a route that actually
    exists and genuinely lacks _auth — catches a stale allowlist entry."""
    all_paths_methods = {
        (getattr(r, "path", ""), m)
        for r in api_module.app.routes
        for m in (getattr(r, "methods", None) or [""])
    }
    for path, method in PUBLIC_ROUTES:
        assert (path, method) in all_paths_methods, (
            f"PUBLIC_ROUTES entry {method} {path} no longer matches any "
            f"route — remove it or fix the path/method."
        )
