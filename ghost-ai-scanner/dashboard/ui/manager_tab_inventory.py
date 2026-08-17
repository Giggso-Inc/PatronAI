# =============================================================
# FILE: dashboard/ui/manager_tab_inventory.py
# VERSION: 2.2.0
# UPDATED: 2026-05-11
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Inventory tab — asset metrics, CrowdStrike banner, asset table.
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial
#   v2.0.0  2026-04-27  Fix asset key + owner attribution for mixed
#                       network/endpoint event streams.
#   v2.1.0  2026-04-28  Add ?view=user_detail hyperlink on OWNER column.
#   v2.2.0  2026-05-11  KPI bug fix — "Endpoints" / "Cloud Instances"
#                       were counting EVENT ROWS (1 laptop with 1020
#                       scan events showed Endpoints=1020). Now counts
#                       DISTINCT DEVICES via _asset_key. Labels
#                       renamed Endpoints→Devices, Cloud Instances→
#                       Cloud Hosts. Adds a small "Scan Events" line
#                       under each card to preserve the volume signal
#                       without conflating it with device count.
# =============================================================

import os
from collections import defaultdict

import streamlit as st

from .helpers          import sev_badge
from .filtered_table   import search_box, apply_search_dicts
from .clickable_metric import clickable_metric, static_metric
from .drill_panel      import render_drill_panel
from .ai_posture_card  import render_ai_posture
from .policy_context_loader import load_org_policy_context

_PANEL = "mgr_inventory"

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}


def _asset_key(e: dict) -> str:
    """Best identifier for grouping: device_id > src_hostname > src_ip."""
    return (e.get("device_id") or e.get("src_hostname") or
            e.get("src_ip") or "unknown")


def _owner_of(e: dict) -> str:
    """Authenticated identity: email (endpoint agent) > owner (network)."""
    return (e.get("email") or e.get("owner") or "").strip()


def render_inventory(events: list) -> None:
    """AI Posture card (headline) → KPI cards → asset table."""
    q = search_box("inventory", placeholder="search owner / IP / MAC …")
    if q:
        events = apply_search_dicts(events, q)

    keys = [_asset_key(e) for e in events]
    unique_keys = list(dict.fromkeys(keys))

    # Headline — aggregated AI Posture card. Single risk score +
    # per-category breakdown replaces the count-of-everything KPI noise.
    # When compacted findings_current rows are available they're used;
    # otherwise we degrade gracefully to raw events.
    device_label = unique_keys[0] if len(unique_keys) == 1 else f"{len(unique_keys)} devices"
    # Per-device scores -> worst-case-blend fleet number. Decomposable:
    # the per-device numbers also appear in the ASSET INVENTORY SCORE column.
    # Each device is scored with its OWNER's EFFECTIVE policy (org + their
    # teams + their own list) so the SCORE column matches the User-detail page.
    from scoring.risk_score import risk_score as _rs, risk_band as _rb
    from scoring.breakdown import fleet_blend as _blend
    from .policy_context_loader import load_user_policy_context
    _dev_events: dict = defaultdict(list)
    _dev_owner: dict = {}
    for _e in events:
        _k = _asset_key(_e)
        _dev_events[_k].append(_e)
        _o = (_e.get("email") or _e.get("owner") or "").strip()
        if _o and not _dev_owner.get(_k):
            _dev_owner[_k] = _o
    _ctx_cache: dict = {}   # resolve each owner's effective context once per render

    def _owner_ctx(owner_email: str):
        if not owner_email:
            return load_org_policy_context()
        if owner_email not in _ctx_cache:
            _ctx_cache[owner_email] = load_user_policy_context(owner_email)
        return _ctx_cache[owner_email]

    dev_score = {k: _rs(evs, _owner_ctx(_dev_owner.get(k, "")))
                 for k, evs in _dev_events.items()}
    _scores = list(dev_score.values())
    _note = (f"Fleet = 60% x worst device ({max(_scores)}) + 40% x avg "
             f"({round(sum(_scores) / len(_scores))}) across {len(_scores)} device(s)"
             if _scores else "")
    # fleet_score drives the headline, so policy_context is unused here.
    render_ai_posture(events, device_label=device_label, policy_context=None,
                      fleet_score=_blend(_scores), score_note=_note)

    # KPIs count DISTINCT DEVICES, not event rows. A laptop emitting a
    # scan every 30 min must show as 1 device + N scan events, never
    # as N "endpoints". The pre-2.2.0 sum() over events.asset_type was
    # the source of the inflated 1020 figure customers were seeing.
    laptop_devices = len({_asset_key(e) for e in events
                          if e.get("asset_type") == "laptop"})
    cloud_devices  = len({_asset_key(e) for e in events
                          if e.get("asset_type") == "ec2"})
    with_ai        = len({_asset_key(e) for e in events
                          if e.get("outcome") == "ENDPOINT_FINDING"})

    # Volume signals — preserved but shown beneath the device counts so
    # the operator can still see "1 device, 1020 scan events" at a glance.
    laptop_events = sum(1 for e in events if e.get("asset_type") == "laptop")
    cloud_events  = sum(1 for e in events if e.get("asset_type") == "ec2")
    ai_events     = sum(1 for e in events if e.get("outcome") == "ENDPOINT_FINDING")

    c1, c2, c3, c4 = st.columns(4)
    static_metric(c1,    "Total Assets",    len(unique_keys))
    clickable_metric(c2, "Devices",         laptop_devices,
                     panel_key=_PANEL, drill_field="asset_type",
                     drill_value="laptop", drill_label="Asset = laptop",
                     sub_label=f"{laptop_events} scan events")
    clickable_metric(c3, "Cloud Hosts",     cloud_devices,
                     panel_key=_PANEL, drill_field="asset_type",
                     drill_value="ec2", drill_label="Asset = ec2",
                     sub_label=f"{cloud_events} scan events")
    clickable_metric(c4, "With AI Events",  with_ai,
                     panel_key=_PANEL, drill_field="outcome",
                     drill_value="ENDPOINT_FINDING",
                     drill_label="Endpoint findings",
                     sub_label=f"{ai_events} findings")
    render_drill_panel(_PANEL, events, limit=100)

    if not os.environ.get("CROWDSTRIKE_ENABLED", "false").lower() == "true":
        # Neutral informational banner — NOT a warning. The default
        # PatronAI hook agent already provides per-process visibility
        # every 30 min; an EDR (CrowdStrike, SentinelOne, etc.) just
        # adds continuous kernel-level telemetry. Most operators do
        # not have or need this. Wording stays soft so the dashboard
        # doesn't suggest something is broken when nothing is.
        st.markdown(
            '<div style="background:rgba(31,111,235,.05);border:1px solid rgba(31,111,235,.20);'
            'border-radius:6px;padding:9px 14px;margin:12px 0;'
            'font-family:JetBrains Mono;font-size:11px;color:#57606A;">'
            'ⓘ EDR not configured. Process visibility comes from the '
            'PatronAI hook agent (30-min cycle). Set '
            '<code style="background:transparent;color:inherit">'
            'CROWDSTRIKE_ENABLED=true</code> in <code style="background:transparent;'
            'color:inherit">.env</code> to layer in continuous EDR telemetry.</div>',
            unsafe_allow_html=True,
        )

    # ── Build per-asset rows ──────────────────────────────────
    by_asset: dict = defaultdict(lambda: {
        "count": 0, "severity": "CLEAN",
        "owner": "", "dept": "", "mac": "", "type": "",
    })
    for e in events:
        key  = _asset_key(e)
        a    = by_asset[key]
        a["count"] += 1 if e.get("outcome") != "SUPPRESS" else 0

        # Owner: prefer authenticated email; only replace if current is blank
        new_owner = _owner_of(e)
        if new_owner and (not a["owner"] or e.get("email")):
            a["owner"] = new_owner

        if e.get("department"):
            a["dept"] = e["department"]
        if e.get("mac_address"):
            a["mac"] = e["mac_address"]
        if e.get("asset_type"):
            a["type"] = e["asset_type"]

        ev_sev  = (e.get("severity") or "CLEAN").upper()
        cur_sev = a["severity"]
        if _SEV_RANK.get(ev_sev, 0) > _SEV_RANK.get(cur_sev, 0):
            a["severity"] = ev_sev

    def _asset_row(key: str, v: dict) -> str:
        owner = v["owner"] or "—"
        # Link owner email to user detail page
        owner_cell = (
            f"<a href='?view=user_detail&email={owner}' "
            f"style='color:#0969DA;text-decoration:none'>{owner}</a>"
            if "@" in owner else owner
        )
        return (
            f"<tr>"
            f"<td style='font-family:JetBrains Mono;font-size:11px;color:#57606A'>"
            f"{key}</td>"
            f"<td>{v['type'] or '—'}</td>"
            f"<td>{owner_cell}</td>"
            f"<td>{v['dept'] or '—'}</td>"
            f"<td style='font-family:JetBrains Mono;font-size:10px;color:#57606A'>"
            f"{v['mac'] or '—'}</td>"
            f"<td style='text-align:center'>{v['count']}</td>"
            f"<td style='text-align:center;font-family:JetBrains Mono;font-weight:600'>"
            f"{dev_score.get(key, 0)} <span style='color:#57606A;font-weight:400'>"
            f"/100</span></td>"
            f"<td>{sev_badge(_rb(dev_score.get(key, 0)) if v['count'] > 0 else 'CLEAN')}</td>"
            f"</tr>"
        )

    rows = "".join(
        _asset_row(key, v)
        for key, v in sorted(by_asset.items(),
                              key=lambda x: x[1]["count"], reverse=True)[:20]
    )
    st.markdown('<div class="card-title">ASSET INVENTORY</div>',
                unsafe_allow_html=True)
    # "DEVICE NAME", not "SOURCE IP / DEVICE": _asset_key resolves
    # src_hostname before src_ip, and endpoint-agent events always set
    # src_hostname — so this column cannot render an IP while agent events
    # are the only source. Kept in step with commonFE's Shadow AI table
    # (ShadowAI.jsx), which routers/ravenhub.py mirrors field-for-field.
    st.markdown(
        f"<table><thead><tr>"
        f"<th>DEVICE NAME</th><th>TYPE</th><th>USER</th>"
        f"<th>DEPT</th><th>MAC</th><th>EVENTS</th><th>SCORE</th><th>STATUS</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>",
        unsafe_allow_html=True,
    )
