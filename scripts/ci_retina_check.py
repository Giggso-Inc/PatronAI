"""ci_retina_check.py — RavenHub Card CI gate.

Fetches the estate people list from RavenHub and verifies that the PR author
has at least one device in a matched, fresh state. Exits 0 (pass) or 1 (fail)
so the GitHub Actions step result propagates to the PR check.

Environment variables:
  RAVEN_HUB_URL   — Hub base URL, e.g. https://gsd.giggso.com  (required)
  RAVEN_AGENT_KEY — Shared org-wide agent key (same as Hub's RAVEN_AGENT_KEY
                    env var). Sent as X-Raven-Agent header.     (required)
  RAVEN_ORG       — Org slug, e.g. giggso                      (required)
  PR_AUTHOR_EMAIL — Email of the PR author. GitHub only populates this for
                    users with a public GitHub email; absent for most users.
  PR_AUTHOR_LOGIN — GitHub login of the PR author. Fallback email source.
  GITHUB_TOKEN    — Auto-provided by Actions. Used to read PR commit emails
                    (the git-configured email, usually the corporate address).
  PR_NUMBER       — PR number. Used with GITHUB_TOKEN for commit lookup.

Optional:
  GITHUB_API_URL  — GitHub API base (default https://api.github.com)

Stdlib only — no pip installs needed in CI.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HUB_URL       = (os.environ.get("RAVEN_HUB_URL") or "").rstrip("/")
API_KEY       = os.environ.get("RAVEN_AGENT_KEY") or ""
ORG           = os.environ.get("RAVEN_ORG") or "giggso"
AUTHOR_EMAIL  = (os.environ.get("PR_AUTHOR_EMAIL") or "").strip()
AUTHOR_LOGIN  = (os.environ.get("PR_AUTHOR_LOGIN") or "").strip()
GITHUB_TOKEN  = (os.environ.get("GITHUB_TOKEN") or "").strip()
GITHUB_REPO   = (os.environ.get("GITHUB_REPOSITORY") or "").strip()
PR_NUMBER     = (os.environ.get("PR_NUMBER") or "").strip()
GITHUB_API    = (os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")

# Statuses that block CI. The age check (RETINA_MAX_AGE / BR-03) is intentionally
# NOT applied here — that check belongs on the local retina-gate hook (per-tool-call).
# The CI gate's job is: "is this developer onboarded and trusted by a security admin?"
# The Hub's own staleness job sets status="stale" when PatronAI stops reporting;
# that status transition is what blocks CI, not wall-clock scan age.
_BLOCKING_STATUSES = {"mismatched", "stale", "rejected", "access_revoked", "pending_enroll"}


def _fail(msg: str) -> None:
    print(f"::error::Raven Retina Check FAILED — {msg}")
    sys.exit(1)


def _pass(msg: str) -> None:
    print(f"Raven Retina Check PASSED — {msg}")
    sys.exit(0)


def _resolve_author_email() -> str:
    """Return the PR author's email using the best available source.

    Resolution order:
    1. PR_AUTHOR_EMAIL (set by GitHub only when user's email is public — rare)
    2. Commit author email from PR commits via authenticated GitHub API
       (GITHUB_TOKEN is always available in Actions; the git-configured email
       is usually the corporate email that matches the Hub record)
    3. Public user profile email (GitHub /users/{login} — usually null for
       private emails, kept as last resort)
    """
    if AUTHOR_EMAIL:
        return AUTHOR_EMAIL

    # Try commit email — most reliable for users with private GitHub emails.
    if GITHUB_TOKEN and GITHUB_REPO and PR_NUMBER:
        url = f"{GITHUB_API}/repos/{GITHUB_REPO}/pulls/{PR_NUMBER}/commits"
        try:
            req = urllib.request.Request(url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {GITHUB_TOKEN}",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                commits = json.loads(resp.read().decode())
            if commits:
                # Use the most recent commit's author email; skip noreply addresses.
                for commit in reversed(commits):
                    email = (commit.get("commit", {}).get("author", {}).get("email") or "").strip()
                    if email and not email.endswith("@users.noreply.github.com"):
                        return email
        except Exception:
            pass

    # Last resort: public profile (often null for private-email users).
    if not AUTHOR_LOGIN:
        return ""
    try:
        req = urllib.request.Request(
            f"{GITHUB_API}/users/{AUTHOR_LOGIN}",
            headers={"Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return (data.get("email") or "").strip()
    except Exception:
        return ""


def _hub_get(path: str, params: dict | None = None) -> dict | list:
    """GET path from Hub with Bearer auth. Raises on non-200.

    params: optional dict of query parameters — values are URL-encoded via
    urllib.parse.quote before appending, so callers pass raw strings."""
    if params:
        qs = "&".join(
            f"{k}={urllib.parse.quote(str(v), safe='')}"
            for k, v in params.items()
        )
        path = f"{path}?{qs}"
    url = f"{HUB_URL}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "X-Raven-Agent": API_KEY,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"Hub returned {e.code} for {url}: {body}") from e
    except Exception as e:
        raise RuntimeError(f"Hub request failed for {url}: {e}") from e


def main() -> None:
    # ── Preflight checks ────────────────────────────────────────────────────
    if not HUB_URL:
        _fail("RAVEN_HUB_URL is not set. Add it as a repository secret.")
    if not API_KEY:
        _fail("RAVEN_AGENT_KEY is not set. Add it as a repository secret (same value as Hub's RAVEN_AGENT_KEY env var).")
    AUTHOR = _resolve_author_email()
    if not AUTHOR:
        _fail(
            "Cannot resolve PR author email. Set PR_AUTHOR_EMAIL in the workflow, or "
            "ensure PR_AUTHOR_LOGIN is set and the author's GitHub email is public."
        )

    print(f"Raven Retina Check: org={ORG!r} author={AUTHOR!r}")

    # ── Fetch only the author's cards (email filter — one DB row, not all org) ─
    try:
        people = _hub_get("/api/v1/estate/people", params={"org": ORG, "email": AUTHOR})
    except RuntimeError as e:
        # Fail-closed: a Hub outage is an unknown state, not a confirmed pass.
        # Silently passing PRs when the security gate is unreachable defeats
        # the purpose of the gate. Teams should fix the Hub connection rather
        # than bypass it.
        _fail(f"Hub unreachable — cannot verify device trust: {e}")

    if not isinstance(people, list):
        _fail(f"Unexpected response shape from Hub: {type(people)}")

    # ── Find the author ──────────────────────────────────────────────────────
    # Hub already filtered by email server-side; the list is 0 or 1 person.
    # Local loop is belt-and-braces in case of unexpected response shapes.
    author_lower = AUTHOR.lower()
    matched_person = None
    for person in people:
        if (person.get("person_email") or "").lower() == author_lower:
            matched_person = person
            break

    if matched_person is None:
        _fail(
            f"No host card found for author {AUTHOR!r}. "
            f"This developer has not been onboarded to RavenHub. "
            f"Ask a security admin to issue a device token at "
            f"{HUB_URL}/api/v1/devices/token/emit."
        )

    # ── Check host statuses ──────────────────────────────────────────────────
    hosts = matched_person.get("hosts") or []
    if not hosts:
        _fail(f"Author {AUTHOR!r} is in the estate but has no host cards yet.")

    # Look for at least one host with status=matched. Scan age is not checked
    # here — the local retina-gate hook (per-tool-call) enforces freshness.
    # The Hub's staleness job transitions status to "stale" when PatronAI stops
    # reporting; that status change is what blocks CI, not wall-clock scan age.
    passing_host = None
    reasons: list[str] = []
    for host in hosts:
        status  = host.get("status", "unknown")
        host_id = host.get("host_id", "?")

        if status in _BLOCKING_STATUSES:
            reasons.append(f"{host_id}: status={status}")
            continue
        if status != "matched":
            reasons.append(f"{host_id}: status={status} (unrecognised)")
            continue
        passing_host = host
        break

    if passing_host is None:
        reason_str = "; ".join(reasons) if reasons else "unknown"
        _fail(
            f"No trusted device found for author {AUTHOR!r}. "
            f"Details: {reason_str}. "
            f"The developer's device status must be 'matched' on RavenHub. "
            f"A security admin can review device trust at {HUB_URL}."
        )

    age = passing_host.get("age_seconds")
    age_note = f", last scanned {int(age)}s ago" if age is not None else ""
    _pass(f"Author {AUTHOR!r} has a trusted device ({passing_host['host_id']}{age_note}).")


if __name__ == "__main__":
    main()
