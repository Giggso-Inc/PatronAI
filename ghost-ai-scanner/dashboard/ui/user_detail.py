# =============================================================
# FILE: dashboard/ui/user_detail.py
# PROJECT: PatronAI — Mega-PR
# VERSION: 1.1.0
# UPDATED: 2026-04-28
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Per-user detail page — opened by clicking an email or
#          agent-fleet name. Two tabs:
#            ASSETS — Mind map (replaces treemap; render_user_mindmap)
#            LOGS   — Recent events for this user, filterable.
# DEPENDS: streamlit, ai_inventory_mindmap, time_fmt
# AUDIT LOG:
#   v1.0.0  2026-04-27  Initial. Mega-PR.
#   v1.1.0  2026-04-28  Replace treemap with render_user_mindmap.
# =============================================================

import streamlit as st

from .ai_inventory_mindmap import render_user_mindmap
from .time_fmt             import fmt as fmt_time
from .helpers          import sev_badge, geo_flag
from .filtered_table   import search_box, apply_search_dicts


def render_user_detail(events: list, email: str) -> None:
    """Two-tab per-user page. `events` is the full event list."""
    if not email:
        st.warning("No user selected.")
        return

    st.markdown(f"### User detail — `{email}`")
    user_events = [e for e in events
                   if (e.get("email") or e.get("owner") or "") == email]
    st.caption(f"{len(user_events)} total event(s) for this user.")

    t0, t1, t2 = st.tabs(["  SCORE  ", "  ASSETS  ", "  LOGS  "])
    with t0:
        _render_score_breakdown(user_events, email)
    with t1:
        render_user_mindmap(events, email)
    with t2:
        _render_logs(user_events)

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("← back"):
        st.query_params.clear()
        st.rerun()


# ADR_2026-07-31: no more Giggso tier/override tiers — org owns the only
# deny list; scoring waterfall is scope-first (user > project > org).
_TIER_LABEL = {
    "org_deny": "🔴 Org deny", "project_deny": "🔴 Project deny",
    "user_deny": "🔴 User deny", "org_approve": "🟢 Org approved",
    "project_approve": "🟢 Project approved", "user_ack": "🟢 User approved",
    "unknown": "⚪ Unclassified — pending review",
}

# Severity dot shown on the COLLAPSED category bar (so severity reads before opening).
_SEV_DOT = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "CLEAN": "🟢"}

# Human-readable category titles (e.g. ide_plugin -> "IDE Plugin").
_CATEGORY_LABEL = {
    "ide_plugin": "IDE Plugin", "mcp_server": "MCP Server", "vector_db": "Vector DB",
    "browser": "Browser (AI)", "package": "Package", "process": "Process",
    "shell_history": "Shell History", "tool_registration": "Tool Registration",
    "agent_workflow": "Agent Workflow", "agent_scheduled": "Scheduled Agent",
    "container_image": "Container Image", "container_log_signal": "Container Log",
    "unknown": "Unknown",
}


def _render_score_breakdown(user_events: list, email: str = "") -> None:
    """Full per-provider derivation of this user's risk score, using the
    user's EFFECTIVE policy (org + their projects + their own list)."""
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    from scoring.breakdown import score_detail
    from .policy_context_loader import load_user_policy_context

    d = score_detail(user_events, load_user_policy_context(email))
    band_color = {"CRITICAL": "#cf222e", "HIGH": "#bc4c00", "MEDIUM": "#9a6700",
                  "LOW": "#1f6feb", "CLEAN": "#1a7f37"}.get(d["band"], "#57606A")
    # Light severity tints — convey severity without loud HIGH/MEDIUM/LOW labels.
    tint = {"CRITICAL": "#fde7ea", "HIGH": "#fdeee2", "MEDIUM": "#fcf7e3",
            "LOW": "#eef4fc", "CLEAN": "#eafaf0"}

    st.markdown(
        f"<div style='font-family:JetBrains Mono;font-size:15px;font-weight:700;"
        f"color:{band_color};margin:4px 0 2px'>RISK SCORE: {d['score']} / 100 · {d['band']}"
        f"</div>", unsafe_allow_html=True,
    )
    provs = d["providers"]
    if not provs:
        st.success("No open findings for this user — clean.")
        return
    with st.expander("How is this scored?"):
        st.caption(
            f"Worst provider weight {d['worst']} sets the floor; {d['risky_count']} risky "
            "provider(s) add breadth. Approved tools weigh x0.1-0.5, denied x2-3. "
            "Score = floor + (100 - floor) x breadth x 0.5.")

    from collections import defaultdict
    groups: dict = defaultdict(list)
    for p in provs:
        groups[p["category"] or "unknown"].append(p)
    # Categories sorted by total weight (highest first).
    ordered = sorted(groups.items(), key=lambda kv: -sum(x["weighted"] for x in kv[1]))

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for idx, (cat, items) in enumerate(ordered):
        items = sorted(items, key=lambda x: -x["weighted"])   # providers: heaviest first
        total = round(sum(x["weighted"] for x in items), 1)
        max_sev = max(items, key=lambda x: sev_rank.get(x["severity"], 0))["severity"]
        dot = _SEV_DOT.get(max_sev, "⚪")
        title = _CATEGORY_LABEL.get(cat, cat.replace("_", " ").title())
        with st.expander(f"{dot} {title}  ·  {len(items)} provider(s)  ·  weight {total}",
                         expanded=(idx == 0)):
            rows_html = "".join(
                f"<tr style='background:{tint.get(p['severity'], '#ffffff')}'>"
                f"<td style='font-family:JetBrains Mono;font-size:11px'>{p['provider'][:48]}</td>"
                f"<td style='text-align:center'>{p['occurrences']}</td>"
                f"<td style='font-size:11px'>{_TIER_LABEL.get(p['tier'], p['tier'])}</td>"
                f"<td style='text-align:center'>×{p['multiplier']}</td>"
                f"<td style='text-align:center;font-weight:700'>{p['weighted']}</td>"
                f"</tr>"
                for p in items
            )
            st.markdown(
                f"<div style='overflow-x:auto'><table><thead><tr>"
                f"<th>PROVIDER</th><th>OCCUR</th><th>POLICY</th><th>MULT</th><th>WEIGHT</th>"
                f"</tr></thead><tbody>{rows_html}</tbody></table></div>",
                unsafe_allow_html=True,
            )


def _render_logs(user_events: list) -> None:
    """Logs tab — recent events for this user, with global search."""
    if not user_events:
        st.info("No log events for this user yet.")
        return

    q = search_box("user_detail_logs",
                   placeholder="search any column …")
    rows_in = sorted(user_events,
                     key=lambda e: e.get("timestamp", ""), reverse=True)
    rows_in = apply_search_dicts(rows_in, q)[:200]
    if not rows_in:
        st.caption("No matching events.")
        return

    rows_html = "".join(
        f"<tr>"
        f"<td style='font-family:JetBrains Mono;font-size:10px;color:#57606A'>"
        f"{fmt_time(e.get('timestamp'))}</td>"
        f"<td style='font-family:JetBrains Mono;font-size:11px'>"
        f"{e.get('src_ip', e.get('device_id', '—'))}</td>"
        f"<td style='font-family:JetBrains Mono;font-size:11px'>"
        f"{(e.get('provider') or '—')[:60]}</td>"
        f"<td>{sev_badge(e.get('severity', 'UNKNOWN'))}</td>"
        f"<td style='font-family:JetBrains Mono;font-size:10px;color:#57606A'>"
        f"{(e.get('source') or '—')[:30]}</td>"
        f"<td style='font-family:JetBrains Mono;font-size:10px'>"
        f"{geo_flag(e.get('geo_country',''))} {e.get('geo_country','')}</td>"
        f"</tr>"
        for e in rows_in
    )
    st.markdown(
        f'<div class="card-title">RECENT EVENTS — {len(rows_in)} ROWS</div>'
        f"<div style='overflow-x:auto;max-height:480px;overflow-y:auto'>"
        f"<table><thead><tr>"
        f"<th>TIMESTAMP</th><th>DEVICE / IP</th><th>PROVIDER</th>"
        f"<th>SEV</th><th>SOURCE</th><th>GEO</th>"
        f"</tr></thead><tbody>{rows_html}</tbody></table></div>",
        unsafe_allow_html=True,
    )
