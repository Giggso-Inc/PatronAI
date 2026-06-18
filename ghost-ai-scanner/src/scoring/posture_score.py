# =============================================================
# FILE: src/scoring/posture_score.py
# VERSION: 1.0.0
# UPDATED: 2026-06-18
# OWNER: Giggso Inc
# PURPOSE: Pure scoring functions for the 7-component AI-governance
#          posture score (0-100). No I/O — fully unit-testable.
#          Called by score_api.py; also importable from the dashboard.
# BANDS:
#   GOOD     85-100   Healthy AI usage.
#   FAIR     65-84    Soft gaps — nudge via dashboard.
#   POOR     40-64    Multiple gaps — manager review.
#   CRITICAL  0-39    Hard policy breach — same-day action.
# AUDIT LOG:
#   v1.0.0  2026-06-18  Initial.
# =============================================================

import fnmatch
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

log = logging.getLogger("marauder-scan.posture_score")

# ── Weights (must sum to 100) ─────────────────────────────────────────────────
WEIGHTS: dict[str, int] = {
    "approved_tools":    30,
    "no_ghost_assets":   20,
    "mcp_hygiene":       20,
    "no_high_findings":  10,
    "domain_compliance": 10,
    "provider_count":     5,
    "identity_binding":   5,
}

# ── Scoring constants ─────────────────────────────────────────────────────────
GHOST_THRESHOLD_DAYS   = 30
GHOST_COST_PTS         = 2    # points lost per ghost asset
MCP_UNSCOPED_COST      = 8    # points lost per unscoped-root filesystem MCP server
MCP_UNAPPROVED_COST    = 4    # points lost per non-approved MCP server
HIGH_FINDING_COST      = 5    # points lost per open HIGH finding
PROVIDER_RATIO_FULL    = 1.5  # user/org ratio ≤ this → full 5 pts
PROVIDER_RATIO_PARTIAL = 2.5  # user/org ratio ≤ this → 2 pts; above → 0
HEARTBEAT_MAX_AGE_H    = 24   # hours — older heartbeat → identity binding fails

# Scope-bounding flag prefixes for MCP filesystem servers.
# A server that advertises any of these in its arg_flags is considered bounded.
_SCOPE_FLAGS = ("--root", "--allow", "--dir", "--path", "--scope", "--base")

BANDS = [(85, "GOOD"), (65, "FAIR"), (40, "POOR"), (0, "CRITICAL")]


# ── Helpers ───────────────────────────────────────────────────────────────────

def score_band(score: int) -> str:
    for threshold, band in BANDS:
        if score >= threshold:
            return band
    return "CRITICAL"


def is_approved_provider(provider: str, approved: set) -> bool:
    """Return True if provider matches any entry in the approved set.
    Supports exact match and glob patterns (fnmatch)."""
    p = provider.strip().lower()
    if not p:
        return False
    if p in approved:
        return True
    return any(fnmatch.fnmatch(p, pat) for pat in approved if "*" in pat or "?" in pat)


def build_approved_set(
    authorized_csv: list[dict],
    authorized_code_csv: list[dict],
    per_user_domains: list[str],
) -> set:
    """Merge all three approved-list sources into one normalised set."""
    out: set = set()
    for row in authorized_csv:
        for col in ("name", "domain_pattern"):
            v = (row.get(col) or "").strip().lower()
            if v and not v.startswith("#"):
                out.add(v)
    for row in authorized_code_csv:
        for col in ("name", "pattern"):
            v = (row.get(col) or "").strip().lower()
            if v and not v.startswith("#"):
                out.add(v)
    for d in per_user_domains:
        v = d.strip().lower()
        if v:
            out.add(v)
    return out


def _findings(events: list) -> list:
    """Filter to ENDPOINT_FINDING events only."""
    return [e for e in events if e.get("outcome") == "ENDPOINT_FINDING"]


# ── Component scorers ─────────────────────────────────────────────────────────
# Each returns (earned: int, detail: dict).

def c_approved_tools(user_events: list, approved: set) -> tuple[int, dict]:
    """30 pts · Pro-rated by fraction of events from approved providers."""
    evts = _findings(user_events)
    if not evts:
        return 30, {"reason": "no_events_in_period"}
    approved_evts = [e for e in evts if is_approved_provider(e.get("provider") or "", approved)]
    ratio = len(approved_evts) / len(evts)
    earned = round(30 * ratio)
    unapproved = sorted({
        e.get("provider") or "" for e in evts
        if not is_approved_provider(e.get("provider") or "", approved)
    } - {""})
    return earned, {
        "ratio": round(ratio, 3),
        "approved_events": len(approved_evts),
        "total_events": len(evts),
        "unapproved_providers": unapproved,
    }


def c_ghost_assets(user_events: list, period_end: str) -> tuple[int, dict]:
    """20 pts · -2 per asset with last_seen > 30 days before period_end."""
    try:
        cutoff = (datetime.fromisoformat(period_end) - timedelta(days=GHOST_THRESHOLD_DAYS)).date().isoformat()
    except Exception:
        cutoff = ""

    # Latest timestamp per unique (category, provider) asset
    assets: dict = {}
    for e in _findings(user_events):
        key = (e.get("category") or "", e.get("provider") or "")
        ts = (e.get("last_seen") or e.get("timestamp") or "")[:10]
        if key not in assets or ts > assets[key]:
            assets[key] = ts

    ghosts = [
        {"category": k[0], "provider": k[1], "last_seen": v}
        for k, v in assets.items()
        if v and cutoff and v < cutoff
    ]
    earned = max(0, 20 - len(ghosts) * GHOST_COST_PTS)
    return earned, {"ghost_count": len(ghosts), "cutoff_date": cutoff, "ghost_assets": ghosts}


def c_mcp_hygiene(user_events: list, approved: set) -> tuple[int, dict]:
    """20 pts · -8 per unscoped-root filesystem server; -4 per non-approved server."""
    mcp_evts = [
        e for e in user_events
        if e.get("category") == "mcp_server" and e.get("outcome") == "ENDPOINT_FINDING"
    ]
    earned = 20
    violations: list = []

    # Dedup by server_name — one deduction per distinct server
    seen: dict = {}
    for e in mcp_evts:
        sname = (e.get("server_name") or e.get("provider") or "").strip()
        if sname and sname not in seen:
            seen[sname] = e

    for sname, event in seen.items():
        sl = sname.lower()
        cmd = (event.get("command_basename") or "").lower()
        arg_flags: list = event.get("arg_flags") or []

        is_filesystem = "filesystem" in sl or "filesystem" in cmd
        if is_filesystem:
            # Scanner strips positional args — only flag-shaped args are stored.
            # No scope flags → treat as unscoped root.
            has_scope = any(
                isinstance(f, str) and f.startswith(_SCOPE_FLAGS)
                for f in arg_flags
            )
            if not has_scope:
                cost = MCP_UNSCOPED_COST
                earned = max(0, earned - cost)
                violations.append({"server": sname, "issue": "unscoped_filesystem_root", "cost": cost})
                continue  # unscoped is the dominant finding; skip approved check

        if not is_approved_provider(sl, approved):
            cost = MCP_UNAPPROVED_COST
            earned = max(0, earned - cost)
            violations.append({"server": sname, "issue": "not_approved", "cost": cost})

    return earned, {"violations": violations}


def c_high_findings(user_events: list) -> tuple[int, dict]:
    """10 pts · -10 for any open CRITICAL; -5 per open HIGH."""
    open_evts = [
        e for e in _findings(user_events) if e.get("status") != "resolved"
    ]
    criticals = [e for e in open_evts if (e.get("severity") or "").upper() == "CRITICAL"]
    highs     = [e for e in open_evts if (e.get("severity") or "").upper() == "HIGH"]

    if criticals:
        return 0, {"open_critical": len(criticals), "open_high": len(highs),
                   "reason": f"{len(criticals)} open CRITICAL finding(s)"}
    if highs:
        earned = max(0, 10 - len(highs) * HIGH_FINDING_COST)
        return earned, {"open_critical": 0, "open_high": len(highs),
                        "reason": f"{len(highs)} open HIGH finding(s)"}
    return 10, {"open_critical": 0, "open_high": 0}


def c_domain_compliance(user_events: list, authorized_domains: list) -> tuple[int, dict]:
    """10 pts · Pro-rated by fraction of per-user authorised domains showing real activity."""
    if not authorized_domains:
        # No per-user domains provisioned; award partial credit to avoid penalising
        # users whose admins have not yet completed onboarding.
        return 5, {"reason": "no_per_user_domains_configured"}

    evts = _findings(user_events)
    active_providers = {(e.get("provider") or "").lower() for e in evts} - {""}
    auth = [d.strip().lower() for d in authorized_domains if d.strip()]
    active_auth = [d for d in auth if any(is_approved_provider(p, {d}) for p in active_providers)]
    coverage = len(active_auth) / len(auth) if auth else 0.0
    earned = max(0, min(10, round(10 * coverage)))

    return earned, {
        "authorized_domain_count": len(auth),
        "active_domain_count": len(active_auth),
        "coverage_ratio": round(coverage, 3),
        "active_providers_sample": sorted(active_providers)[:10],
    }


def c_provider_count(user_events: list, org_events: list) -> tuple[int, dict]:
    """5 pts · User unique providers vs org average.
    ≤ 1.5× → 5; 1.5–2.5× → 2; > 2.5× → 0."""
    user_providers = {e.get("provider") or "" for e in _findings(user_events)} - {""}
    user_cnt = len(user_providers)

    user_prov_map: dict = {}
    for e in org_events:
        if e.get("outcome") != "ENDPOINT_FINDING":
            continue
        u = (e.get("email") or e.get("owner") or "").lower()
        p = e.get("provider") or ""
        if u and p:
            user_prov_map.setdefault(u, set()).add(p)

    org_avg = (
        sum(len(v) for v in user_prov_map.values()) / len(user_prov_map)
        if user_prov_map else 0.0
    )

    if org_avg == 0:
        ratio, earned = 0.0, 5
    else:
        ratio = user_cnt / org_avg
        if ratio <= PROVIDER_RATIO_FULL:
            earned = 5
        elif ratio <= PROVIDER_RATIO_PARTIAL:
            earned = 2
        else:
            earned = 0

    return earned, {
        "user_unique_providers": user_cnt,
        "org_avg_providers": round(org_avg, 1),
        "ratio": round(ratio, 2),
    }


def c_identity_binding(heartbeat: Optional[dict], user_events: list) -> tuple[int, dict]:
    """5 pts · device_uuid + valid MAC + fresh heartbeat + ≥1 device in events."""
    if not heartbeat:
        return 0, {"issues": ["no_heartbeat_data"]}

    issues: list = []
    device_uuid = heartbeat.get("device_uuid") or ""
    mac         = heartbeat.get("mac_primary") or ""
    ts_str      = heartbeat.get("timestamp") or heartbeat.get("time") or ""
    heartbeat_fresh = False

    if not device_uuid:
        issues.append("missing_device_uuid")
    if not mac or mac == "00:00:00:00:00:00":
        issues.append("invalid_or_missing_mac")

    if ts_str:
        try:
            ts    = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            heartbeat_fresh = age_h <= HEARTBEAT_MAX_AGE_H
            if not heartbeat_fresh:
                issues.append(f"heartbeat_stale_{age_h:.0f}h_old")
        except Exception:
            issues.append("unparseable_heartbeat_timestamp")
    else:
        issues.append("missing_heartbeat_timestamp")

    unique_devices = {e.get("device_id") for e in _findings(user_events)} - {"", None}
    if not unique_devices:
        issues.append("no_device_identity_in_events")

    if issues:
        return 0, {
            "issues": issues,
            "device_uuid_present": bool(device_uuid),
            "mac_valid": bool(mac and mac != "00:00:00:00:00:00"),
            "heartbeat_fresh": heartbeat_fresh,
        }
    return 5, {
        "device_uuid": device_uuid,
        "mac_primary": mac,
        "heartbeat_fresh": True,
        "unique_device_count": len(unique_devices),
    }


# ── Full user score ───────────────────────────────────────────────────────────

def compute_user_score(
    user_events: list,
    org_events: list,
    approved_set: set,
    authorized_domains: list,
    heartbeat: Optional[dict],
    period_end: str,
) -> dict:
    """Run all seven components and return the aggregated score dict."""
    components: dict = {}

    def _run(key: str, fn, *args) -> None:
        weight = WEIGHTS[key]
        earned, detail = fn(*args)
        components[key] = {"weight": weight, "earned": earned, "detail": detail}

    _run("approved_tools",    c_approved_tools,    user_events, approved_set)
    _run("no_ghost_assets",   c_ghost_assets,      user_events, period_end)
    _run("mcp_hygiene",       c_mcp_hygiene,       user_events, approved_set)
    _run("no_high_findings",  c_high_findings,     user_events)
    _run("domain_compliance", c_domain_compliance, user_events, authorized_domains)
    _run("provider_count",    c_provider_count,    user_events, org_events)
    _run("identity_binding",  c_identity_binding,  heartbeat, user_events)

    score = sum(v["earned"] for v in components.values())
    return {
        "score": score,
        "band": score_band(score),
        "components": components,
        "improvements": _top_improvements(components),
    }


# ── Improvement suggestions ───────────────────────────────────────────────────

def _top_improvements(components: dict) -> list:
    """Return up to 3 highest-gain improvement actions, ordered by potential gain."""
    candidates: list = []

    def _add(key: str, action: str, priority: int) -> None:
        c = components.get(key, {})
        gap = c.get("weight", 0) - c.get("earned", 0)
        if gap > 0:
            candidates.append({
                "priority": priority,
                "component": key,
                "potential_gain": gap,
                "action": action,
            })

    mcp_detail   = components.get("mcp_hygiene", {}).get("detail", {})
    mcp_violations = mcp_detail.get("violations", [])
    unscoped_svrs  = [v["server"] for v in mcp_violations if "unscoped" in v.get("issue", "")]
    unapproved_svrs = [v["server"] for v in mcp_violations if v.get("issue") == "not_approved"]
    if unscoped_svrs:
        _add("mcp_hygiene",
             f"Restrict {len(unscoped_svrs)} unscoped filesystem MCP server(s) to explicit project "
             f"paths in claude_desktop_config.json, or remove if unused: "
             f"{', '.join(unscoped_svrs[:3])}{'…' if len(unscoped_svrs) > 3 else '.'}", 1)
    elif unapproved_svrs:
        _add("mcp_hygiene",
             f"Register or remove {len(unapproved_svrs)} non-approved MCP server(s): "
             f"{', '.join(unapproved_svrs[:3])}{'…' if len(unapproved_svrs) > 3 else '.'}", 1)

    ghost_detail = components.get("no_ghost_assets", {}).get("detail", {})
    ghosts = ghost_detail.get("ghost_assets", [])
    if ghosts:
        sample = [g["provider"] for g in ghosts[:3]]
        _add("no_ghost_assets",
             f"Remove {len(ghosts)} abandoned AI asset(s) not seen in > {GHOST_THRESHOLD_DAYS} days: "
             f"{', '.join(sample)}{'…' if len(ghosts) > 3 else '.'}", 2)

    tools_detail = components.get("approved_tools", {}).get("detail", {})
    unapproved_p = tools_detail.get("unapproved_providers", [])
    if unapproved_p:
        _add("approved_tools",
             f"File governance tickets to add or remove {len(unapproved_p)} unapproved provider(s): "
             f"{', '.join(unapproved_p[:3])}{'…' if len(unapproved_p) > 3 else '.'}", 3)

    high_detail = components.get("no_high_findings", {}).get("detail", {})
    if high_detail.get("open_critical", 0) or high_detail.get("open_high", 0):
        _add("no_high_findings",
             f"Resolve {high_detail.get('open_critical', 0)} open CRITICAL and "
             f"{high_detail.get('open_high', 0)} open HIGH finding(s).", 4)

    id_detail = components.get("identity_binding", {}).get("detail", {})
    issues = id_detail.get("issues", [])
    if issues:
        _add("identity_binding", f"Fix identity binding: {'; '.join(issues[:3])}.", 5)

    dom_detail = components.get("domain_compliance", {}).get("detail", {})
    if dom_detail.get("coverage_ratio", 1.0) < 0.7:
        _add("domain_compliance",
             f"Improve authorised-domain coverage from "
             f"{dom_detail.get('coverage_ratio', 0):.0%} to ≥ 70 %: ensure the tools listed in "
             f"your per-user authorized_domains are actively in use or update the list to reflect "
             f"your actual AI footprint.", 6)

    prov_detail = components.get("provider_count", {}).get("detail", {})
    if prov_detail.get("ratio", 0) > PROVIDER_RATIO_FULL:
        _add("provider_count",
             f"Reduce unique provider count ({prov_detail.get('user_unique_providers', '?')}) to "
             f"within 1.5× the org average ({prov_detail.get('org_avg_providers', '?')}) by "
             f"consolidating or removing low-use AI tools.", 7)

    candidates.sort(key=lambda c: (-c["potential_gain"], c["priority"]))
    return candidates[:3]
