# =============================================================
# FILE: dashboard/ui/network_view.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc
# PURPOSE: Network view — what a user's machine talked to, and which of it
#          was AI. Five sections: accounts (lead), AI platforms, MCP, SaaS,
#          timeline. Display only; no actions.
# DEPENDS: streamlit, ui.network_data
# =============================================================
"""Network activity, sourced from the capture companion.

SECTION ORDER IS THE DESIGN. Sections are ranked by what a reader acts on,
not by data volume:

  accounts -> AI platforms -> MCP -> SaaS -> timeline

Two accounts on one machine is the finding an auditor opens this tab for, so
it leads. A flow count is not a finding and never leads.

Every number is stated with its verdict ("2 accounts, 1 unattributed"), not
bare ("39,151 flows"), because a bare count gives the reader nothing to do.
"""
import os
from datetime import date, datetime, timedelta, timezone

import streamlit as st

from .network_data import load_findings, owners, summarise

_RANGES = {"24h": 1, "7d": 7, "30d": 30}


def _bar(pct: float, color: str = "#0969DA", h: int = 5) -> str:
    """Inline proportional bar. Streamlit has no primitive for this, and a
    number without a bar makes the reader do the comparison themselves."""
    return (f"<div style='height:{h}px;border-radius:3px;background:#EDF0F3;"
            f"overflow:hidden'><div style='height:100%;width:{max(pct, 1):.1f}%;"
            f"background:{color};border-radius:3px'></div></div>")


def _kpi(col, label: str, value, note: str = "", color: str = ""):
    style = f"color:{color};" if color else ""
    col.markdown(
        f"<div style='font-family:JetBrains Mono;font-size:10px;letter-spacing:.07em;"
        f"text-transform:uppercase;color:#57606A'>{label}</div>"
        f"<div style='font-family:JetBrains Mono;font-size:24px;font-weight:700;"
        f"{style}'>{value}</div>"
        f"<div style='font-size:11px;color:#8B949E'>{note}</div>",
        unsafe_allow_html=True)


def render(store, email: str = "") -> None:
    st.subheader("Network Activity")
    st.caption("What each machine talked to, and which of it was AI. "
               "Connection metadata only — message content is never collected.")

    # ── filters ──────────────────────────────────────────────────────────
    # ONE control owns the period. A fixed From/To alongside a range selector
    # lets the two disagree, with nothing telling the reader which won.
    c1, c2, c3 = st.columns([1.4, 1.2, 1.4])
    period = c2.radio("Period", list(_RANGES) + ["Custom"], horizontal=True,
                      label_visibility="collapsed")

    if period == "Custom":
        d1, d2 = c3.columns(2)
        start = d1.date_input("From", value=date.today() - timedelta(days=1))
        end = d2.date_input("To", value=date.today())
        days = max(1, (end - start).days + 1)
    else:
        days = _RANGES[period]

    all_rows = load_findings(store, days=days)
    if not all_rows:
        st.info(
            "No network activity yet. The capture companion uploads hourly; "
            "findings appear once `tshark_ingest` has run a cycle.\n\n"
            "If a device was enrolled recently, give it an hour.")
        return

    people = owners(all_rows)
    labels = ["All users"] + [lbl for _, lbl in people]
    chosen = c1.selectbox("User", labels, label_visibility="collapsed")
    if chosen != "All users":
        key = next(k for k, lbl in people if lbl == chosen)
        rows = [r for r in all_rows
                if (r.get("owner") or "") == key]
    else:
        rows = all_rows

    s = summarise(rows)

    # ── lead finding: accounts ───────────────────────────────────────────
    # First, and full width, because it is the reason this tab exists.
    unattributed = [a for a in s["accounts"] if not a["office"]]
    if len(s["accounts"]) > 1 and unattributed:
        st.warning(
            f"**{len(s['accounts'])} accounts used from one machine** — "
            f"{len(unattributed)} with no office identity. "
            "An identity with no address at the org domain cannot be tied to "
            "anyone, which is the pattern a personal or side account leaves.")
    for a in s["accounts"]:
        tag = "🟢 Office" if a["office"] else "🟡 Unattributed"
        st.markdown(
            f"{tag} &nbsp; **`{a['identity'] or '—'}`** &nbsp;"
            f"<span style='color:#8B949E;font-family:JetBrains Mono;font-size:11px'>"
            f"account {a['account']} · {a['n']} sign-in(s)</span>",
            unsafe_allow_html=True)

    # ── KPIs ─────────────────────────────────────────────────────────────
    st.markdown("")
    k = st.columns(5)
    ai_flows = sum(c["n"] for c in s["ai"])
    direct_mcp = [m for m in s["mcp"] if m["kind"] != "proxy"]
    proxied = sum(m["n"] for m in s["mcp"] if m["kind"] == "proxy")
    _kpi(k[0], "AI flows", f"{ai_flows:,}",
         f"{ai_flows / s['flows'] * 100:.1f}% of all traffic" if s["flows"] else "",
         "#0969DA")
    _kpi(k[1], "AI platforms", sum(len(c["platforms"]) for c in s["ai"]),
         f"across {len(s['ai'])} categories")
    _kpi(k[2], "MCP servers", len(direct_mcp), f"+{proxied} proxied calls")
    _kpi(k[3], "Accounts", len(s["accounts"]),
         f"{len(unattributed)} unattributed" if unattributed else "all office",
         "#9A6700" if unattributed else "")
    _kpi(k[4], "Flows", f"{s['flows']:,}", f"{s['findings']:,} findings")

    st.divider()

    # ── AI platforms: category -> platform -> domain ─────────────────────
    st.markdown("##### AI platforms")
    if not s["ai"]:
        st.caption("No catalogued AI destinations in this period.")
    cat_max = max((c["n"] for c in s["ai"]), default=1)
    for i, c in enumerate(s["ai"]):
        with st.expander(f"**{c['label']}** — {c['n']:,} flows", expanded=(i < 2)):
            st.markdown(_bar(c["n"] / cat_max * 100), unsafe_allow_html=True)
            p_max = max(x["n"] for x in c["platforms"])
            for p in c["platforms"]:
                st.markdown(f"`{p['p'].replace('_', ' ')}` &nbsp;**{p['n']:,}**",
                            unsafe_allow_html=True)
                rows_html = "".join(
                    f"<tr>"
                    f"<td style='font-family:JetBrains Mono;font-size:11px;"
                    f"color:#57606A;padding:2px 0'>{d['d']}</td>"
                    f"<td style='width:90px;padding:2px 10px'>"
                    f"{_bar(d['n'] / p_max * 100, '#0969DA', 4)}</td>"
                    f"<td style='font-family:JetBrains Mono;font-size:11px;"
                    f"color:#8B949E;text-align:right;width:60px;padding:2px 0'>"
                    f"{d['n']:,}</td></tr>"
                    for d in p["domains"])
                st.markdown(
                    f"<table style='width:100%;margin:2px 0 8px 16px;"
                    f"border-collapse:collapse'>{rows_html}</table>",
                    unsafe_allow_html=True)

    left, right = st.columns([1.15, 1])

    # ── MCP ──────────────────────────────────────────────────────────────
    with left:
        st.markdown("##### MCP servers")
        if s["mcp"]:
            st.dataframe(
                [{"Server": m["d"], "Kind": m["kind"].title(), "Flows": m["n"]}
                 for m in s["mcp"]],
                hide_index=True, use_container_width=True, height=250,
                # NO width="large" on Server: it starves the columns after it
                # and the Flows number gets clipped off the right edge. Let
                # Streamlit distribute, and pin only the two narrow columns.
                column_config={
                    "Kind": st.column_config.TextColumn(width="small"),
                    "Flows": st.column_config.NumberColumn(width="small",
                                                           format="%d")})
            if proxied:
                # This caveat is the point of the panel: a connector call is
                # made by Anthropic's infrastructure, not by this machine, so
                # the endpoint sees a handshake and nothing else.
                st.caption(
                    f"**{proxied} connector calls, servers unknown.** Anthropic's "
                    "proxy runs the call server-side, so the endpoint only sees "
                    "the handshake. Direct servers above were contacted by this "
                    "machine.")
        else:
            st.caption("No MCP activity in this period.")

    # ── SaaS ─────────────────────────────────────────────────────────────
    with right:
        st.markdown("##### SaaS & web apps")
        shown = s["saas"][:40]
        st.dataframe(
            [{"Domain": x["d"], "Scope": "Internal" if x["internal"] else "External",
              "Flows": x["n"]} for x in shown],
            hide_index=True, use_container_width=True, height=250,
            column_config={
                "Scope": st.column_config.TextColumn(width="small"),
                "Flows": st.column_config.NumberColumn(width="small", format="%d")})
        # Say what is NOT shown. "40 rows" without this reads as "40 domains",
        # which can be an order of magnitude off.
        st.caption(f"top {len(shown)} of {len(s['saas'])} domains · no list — "
                   "discovered from evidence only")

    # ── timeline ─────────────────────────────────────────────────────────
    st.markdown("##### Activity by hour")
    # Altair, not st.bar_chart: the point of this chart is that out-of-hours
    # activity looks DIFFERENT, and st.bar_chart paints every bar one colour.
    # Altair ships with Streamlit, so this adds no dependency.
    try:
        import altair as alt
        import pandas as pd
        df = pd.DataFrame([
            {"hour": t["t"], "flows": t["n"],
             "when": "Working hours" if 7 <= int(t["t"]) <= 20 else "Outside hours"}
            for t in s["timeline"]])
        st.altair_chart(
            alt.Chart(df).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2)
            .encode(
                x=alt.X("hour:O", title="hour (UTC)",
                        axis=alt.Axis(labelAngle=0, labelOverlap=False)),
                # Log scale: one hour at 1,483 flows flattens every other bar
                # to a hairline on a linear axis - the quiet hours are exactly
                # what an out-of-hours question is about, so they must stay
                # visible. zero=False because log(0) is undefined.
                y=alt.Y("flows:Q", title="flows",
                        scale=alt.Scale(type="symlog"),
                        axis=alt.Axis(tickCount=5, grid=True)),
                color=alt.Color("when:N",
                                scale=alt.Scale(domain=["Working hours", "Outside hours"],
                                                range=["#0969DA", "#8B949E"]),
                                legend=alt.Legend(title=None, orient="top")),
                tooltip=["hour", "flows", "when"])
            .properties(height=180),
            use_container_width=True)
    except ImportError:
        # Altair missing is not worth losing the section over.
        st.bar_chart({"flows": [t["n"] for t in s["timeline"]]},
                     x_label="hour (UTC)", y_label="flows", height=180)
    off = sum(t["n"] for t in s["timeline"] if int(t["t"]) < 7 or int(t["t"]) > 20)
    if s["flows"]:
        pct = off / s["flows"] * 100
        # "0%" reads as "none happened". Say <1% when it is small but real -
        # 10 out-of-hours flows is a different fact from zero.
        shown = "0%" if off == 0 else ("<1%" if pct < 1 else f"{pct:.0f}%")
        st.caption(f"{shown} of traffic outside working hours (07–20 UTC) · "
                   f"{off:,} of {s['flows']:,} flows")
