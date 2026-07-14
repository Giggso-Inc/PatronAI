# =============================================================
# FILE: dashboard/ui/tabs/provider_governance.py
# VERSION: 4.3.0
# UPDATED: 2026-07-01
# OWNER: Giggso Inc
# PURPOSE: Provider Governance tab. DB mode has two sub-tabs:
#   • Overview — every provider by category with its status at EVERY scope
#     (Giggso / Org / Project / User): 🔴 deny · 🟢 allow · · none.
#   • Manage   — scope selector + Newly Found (grouped by category→family,
#     family-glob one-click + multi-select bulk) + Current lists (sortable
#     tables w/ multiselect remove) + guarded Giggso override.
#   CSV mode (no DATABASE_URL) keeps the simple org allow/block flow.
#   Family collapse uses scoring.provider_family (glob rules; backend already
#   matches globs). Views/CRUD/authz are unit+integration tested.
# AUDIT LOG:
#   v3.0.0  2026-06-30  User-pick scope, scope-effective view, status tags.
#   v4.0.0  2026-07-01  Overview matrix; family grouping + bulk; list tables.
#   v4.1.0  2026-07-01  Manage: read-only "Inherited" table so project/user
#                       scopes surface the Giggso baseline + higher-scope denies
#                       that also govern them (fix: project view showed Blocked:0).
#   v4.2.0  2026-07-01  Inherited now shows (a) OBSERVED baseline/deny hits incl.
#                       overridden ones (State column) + (b) a collapsible FULL
#                       inherited blocklist policy (giggso/org/project deny rules),
#                       so the baseline is visible even with nothing observed.
#   v4.2.1  2026-07-01  Fix: current-lists loop read ApprovedTool-only columns
#                       (valid_until) on BlacklistedTool rows → AttributeError once
#                       a scope had blocked entries. getattr-guarded; +Severity col.
#   v4.3.0  2026-07-01  Manage reordered: Inherited + Override on top (context →
#                       action), then Newly Found, then this-scope lists. Lists
#                       drop the redundant Name column (tailored per model) and
#                       gain a flip action (allow<->block); baseline flip-to-allow
#                       routes through the guarded override (reason required).
# =============================================================

import os
import sys
from collections import defaultdict

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from scoring.provider_views import all_providers, newly_found     # noqa: E402
from scoring.provider_family import is_family, provider_family    # noqa: E402
from . import provider_lists_io as _io                            # noqa: E402

_TAG = {
    "giggso_deny": "🔴 Giggso baseline", "org_deny": "🔴 Org deny",
    "project_deny": "🔴 Project deny", "user_deny": "🔴 User deny",
    "org_approve": "🟢 Org approved", "project_approve": "🟢 Project approved",
    "user_ack": "🟢 User approved", "giggso_override": "🟠 Giggso override (org)",
    "giggso_override_project": "🟠 Giggso override (project)",
    "giggso_override_user": "🟠 Giggso override (user)",
    "unknown": "⚪ Unknown",
}
_CAT_LABEL = {
    "ide_plugin": "IDE Plugin", "mcp_server": "MCP Server", "vector_db": "Vector DB",
    "browser": "Browser (AI)", "package": "Package", "process": "Process",
    "shell_history": "Shell History", "tool_registration": "Tool Registration",
    "agent_workflow": "Agent Workflow", "agent_scheduled": "Scheduled Agent",
    "container_image": "Container Image", "container_log_signal": "Container Log",
    "unknown": "Unknown",
}
_ALLOW_KEY = "config/authorized.csv"; _ALLOW_COLS = ["name", "domain_pattern", "notes"]
_DENY_KEY = "config/unauthorized_custom.csv"
_DENY_COLS = ["name", "category", "domain", "port", "severity", "notes"]


def _cat_title(cat: str) -> str:
    return _CAT_LABEL.get(cat, (cat or "unknown").replace("_", " ").title())


def render(is_admin: bool, events: list, policy_context=None, email: str = "") -> None:
    st.markdown("**Provider Governance** — every AI provider seen, one list per scope.")
    flash = st.session_state.pop("gov_flash", None)
    if flash:
        st.success(flash)
    if os.environ.get("DATABASE_URL"):
        _render_db(is_admin, email, events)
    else:
        providers = all_providers(events, policy_context)
        if not providers:
            st.info("No providers observed yet."); return
        _all_providers_table(providers)
        st.divider()
        _render_csv(is_admin, email, newly_found(events, policy_context))


def _all_providers_table(providers) -> None:
    st.markdown("**All Providers**")
    df = pd.DataFrame([{
        "Provider": p["provider"], "Category": _cat_title(p["category"]),
        "Severity": p["max_severity"], "Findings": p["finding_count"],
        "Status": _TAG.get(p["tier"], p["tier"]), "Weight ×": p["multiplier"],
    } for p in providers])
    q = st.text_input("Filter providers", key="prov_gov_filter").strip().lower()
    if q:
        df = df[df.apply(lambda r: q in " ".join(map(str, r.values)).lower(), axis=1)]
    st.dataframe(df, use_container_width=True, hide_index=True)


# ── DB mode ───────────────────────────────────────────────────────────

def _render_db(is_admin, email, events) -> None:
    try:
        from db.engine import get_session
        from db.policy_queries import get_identity, load_policy_context, project_ids_for_user
        with get_session() as s:
            actor, org_id, _my = get_identity(s, email)
            if actor is None or org_id is None:
                st.warning(f"'{email}' isn't a policy-DB user yet — reload to run the seed.")
                return
            ov, mng = st.tabs(["  Overview  ", "  Manage  "])
            with ov:
                _overview(s, org_id, events)
            with mng:
                scope, project_id, user_id = _scope_selector(s, actor, org_id, is_admin)
                tgt_projects = ([project_id] if scope == "project" and project_id else
                             (project_ids_for_user(s, user_id) if scope == "user" and user_id else []))
                eff = load_policy_context(s, org_id=org_id,
                                          user_id=(user_id if scope == "user" else None),
                                          project_ids=tgt_projects)
                providers = all_providers(events, eff)
                # 1) INHERITED — what governs this scope from above (read-only)
                #    followed by the guarded action that loosens it.
                _inherited_lists(scope, providers, eff)
                _override_section(s, actor, org_id, is_admin, scope, project_id,
                                  user_id, providers)
                st.divider()
                # 2) NEWLY FOUND — triage queue for unclassified providers.
                _newly_found(s, actor, org_id, scope, project_id, user_id,
                             newly_found(events, eff))
                st.divider()
                # 3) THIS-SCOPE lists — editable, with allow<->block flip.
                _current_lists(s, actor, org_id, scope, project_id, user_id)
    except Exception as exc:
        st.error(f"DB governance unavailable: {exc}")


def _overview(s, org_id, events) -> None:
    """Cross-scope matrix: per provider, its status at every scope.
    Project/User cells show the actual NAMES (🟢 allow / 🔴 deny), the first
    two + a '+N' overflow so a long list stays compact."""
    from sqlalchemy import select
    from scoring.policy import _matches, _norm
    from db.models_identity import Project, User
    from db.models_policy import ApprovedTool, BlacklistedTool, GiggsoBaselineDeny

    proj_name = {p.id: p.display_name for p in
                 s.execute(select(Project).where(Project.org_id == org_id)).scalars()}
    user_name = {u.id: (u.display_name or u.email) for u in
                 s.execute(select(User).where(User.org_id == org_id)).scalars()}
    giggso = {_norm(d) for (d,) in s.execute(select(GiggsoBaselineDeny.domain))}
    ap = list(s.execute(select(ApprovedTool).where(ApprovedTool.org_id == org_id)).scalars())
    dn = list(s.execute(select(BlacklistedTool).where(BlacklistedTool.org_id == org_id)).scalars())

    def _org_cell(prov):
        if any(r.scope == "org" and _matches(prov, {_norm(r.domain)}) for r in dn):
            return "🔴"
        if any(r.scope == "org" and _matches(prov, {_norm(r.domain_pattern)}) for r in ap):
            return "🟢"
        return "·"

    def _named_cell(prov, scope, name_map, owner_attr):
        parts = [f"🟢 {name_map.get(getattr(r, owner_attr), '?')}" for r in ap
                 if r.scope == scope and _matches(prov, {_norm(r.domain_pattern)})]
        parts += [f"🔴 {name_map.get(getattr(r, owner_attr), '?')}" for r in dn
                  if r.scope == scope and _matches(prov, {_norm(r.domain)})]
        if not parts:
            return "·"
        return ", ".join(parts[:2]) + (f"  +{len(parts) - 2}" if len(parts) > 2 else "")

    provs = all_providers(events, None)
    if not provs:
        st.info("No providers observed yet."); return
    st.caption("Where each provider stands across scopes — 🟢 allowed · 🔴 denied · · none. "
               "Project/User cells name who set it (first 2, then +N).")
    groups = defaultdict(list)
    for p in provs:
        groups[p["category"] or "unknown"].append(p)
    for cat, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        items = sorted(items, key=lambda x: -x["finding_count"])
        with st.expander(f"{_cat_title(cat)}  ·  {len(items)} provider(s)", expanded=False):
            df = pd.DataFrame([{
                "Provider": p["provider"][:52],
                "Giggso": "🔴" if _matches(p["provider"], giggso) else "·",
                "Org": _org_cell(p["provider"]),
                "Project": _named_cell(p["provider"], "project", proj_name, "project_id"),
                "User": _named_cell(p["provider"], "user", user_name, "user_id"),
            } for p in items])
            st.dataframe(df, use_container_width=True, hide_index=True)


def _scope_selector(s, actor, org_id, is_admin):
    from db.governance_crud import list_org_users, list_projects
    labels = ["Org", "Project (pick)", "User (pick)"]
    scope = {"Org": "org", "Project (pick)": "project", "User (pick)": "user"}[
        st.radio("Manage scope", labels, horizontal=True, key="gov_scope")]
    project_id = user_id = None
    if scope == "project":
        projects = [t for t, _n in list_projects(s, org_id)]
        if projects:
            p = st.selectbox("Project", projects,
                             format_func=lambda x: x.display_name, key="gov_proj_pick")
            project_id = p.id if p is not None else None
        else:
            st.caption("No projects yet — create one in the Projects tab.")
    elif scope == "user":
        users = list_org_users(s, org_id)
        u = st.selectbox("User", users, format_func=lambda x: x.display_name or x.email,
                         key="gov_user_pick")
        user_id = u.id if u is not None else None
    return scope, project_id, user_id


def _flash_and_rerun(msg) -> None:
    st.session_state["gov_flash"] = msg
    st.session_state.pop("policy_ctx_org", None)
    st.rerun()


def _newly_found(s, actor, org_id, scope, project_id, user_id, nf) -> None:
    from db.governance_crud import add_approved, add_blacklisted
    st.markdown(f"**Newly Found** — {len(nf)} provider(s) unclassified at this scope")
    if not nf:
        st.success("Every observed provider is classified at this scope."); return

    def _allow(pattern):
        add_approved(s, actor=actor, org_id=org_id, scope=scope, project_id=project_id,
                     user_id=user_id, name=pattern, provider_pattern=pattern)

    def _block(pattern, sev="HIGH"):
        add_blacklisted(s, actor=actor, org_id=org_id, scope=scope, project_id=project_id,
                        user_id=user_id, domain=pattern, severity=sev)

    by_cat = defaultdict(list)
    for p in nf:
        by_cat[p["category"] or "unknown"].append(p)

    for cat, items in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
        with st.expander(f"{_cat_title(cat)}  ·  {len(items)} provider(s)", expanded=False):
            # Family shortcuts — one glob rule covers all instances of a tool.
            fams = defaultdict(list)
            for p in items:
                if is_family(p["provider"]):
                    fams[provider_family(p["provider"])[1]].append(p)
            for glob, members in sorted(fams.items(), key=lambda kv: -len(kv[1])):
                if len(members) < 2:
                    continue
                c1, c2, c3 = st.columns([4, 1, 1])
                c1.markdown(f"**Family** `{glob}` — {len(members)} instances")
                if c2.button("Allow all", key=f"fa::{scope}::{glob}"):
                    try: _allow(glob); _flash_and_rerun(f"Allowed family `{glob}` at {scope} scope.")
                    except Exception as e: st.error(str(e))
                if c3.button("Deny all", key=f"fd::{scope}::{glob}"):
                    try: _block(glob); _flash_and_rerun(f"Blocked family `{glob}` at {scope} scope.")
                    except Exception as e: st.error(str(e))

            # Individual multi-select + bulk.
            sel = st.multiselect("Select individual providers",
                                 [p["provider"] for p in items], key=f"ms::{scope}::{cat}")
            c1, c2, _ = st.columns([1, 1, 3])
            if c1.button("Allow selected", key=f"as::{scope}::{cat}"):
                if sel:
                    try:
                        for pv in sel: _allow(pv)
                        _flash_and_rerun(f"Allowed {len(sel)} provider(s) at {scope} scope.")
                    except Exception as e: st.error(str(e))
            if c2.button("Block selected", key=f"bs::{scope}::{cat}"):
                if sel:
                    try:
                        for pv in sel: _block(pv)
                        _flash_and_rerun(f"Blocked {len(sel)} provider(s) at {scope} scope.")
                    except Exception as e: st.error(str(e))


# Giggso baseline sits above EVERY scope; org/project denies are inherited by
# the scopes below them. These tiers are read-only in the current scope.
_GIGGSO_TIERS = ("giggso_deny", "giggso_override",
                 "giggso_override_project", "giggso_override_user")
_INHERITED_TIERS = {
    "org":     _GIGGSO_TIERS,
    "project": _GIGGSO_TIERS + ("org_deny",),
    "user":    _GIGGSO_TIERS + ("org_deny", "project_deny"),
}
# Per-tier "State" label for the observed-inherited table.
_STATE = {
    "giggso_deny": "Blocked ×3.0",
    "giggso_override": "Overridden · org ×0.5",
    "giggso_override_project": "Overridden · project ×0.6",
    "giggso_override_user": "Overridden · user ×0.7",
    "org_deny": "Blocked · org",
    "project_deny": "Blocked · project",
}


def _inherited_lists(scope, providers, eff) -> None:
    """What governs this scope but is MANAGED ABOVE it (read-only here):
      1) observed providers that hit an inherited Giggso/org/project rule
         (incl. ones already overridden — shown with their override state);
      2) a collapsible view of the full inherited blocklist *policy*
         (the Giggso baseline + any org/project deny globs), independent of
         what's been observed. A Giggso rule is loosened only via the guarded
         override action below; org/project denies are edited at their scope."""
    tiers = _INHERITED_TIERS.get(scope, ())
    observed = [p for p in providers if p.get("tier") in tiers]
    st.markdown("**Inherited — applies here, managed above**")
    st.caption(f"Governs this {scope} but is set at a higher scope — read-only here. "
               "A Giggso rule is loosened only via the override action below.")
    if observed:
        st.dataframe(pd.DataFrame([{
            "Provider": p["provider"][:52],
            "Rule": _TAG.get(p["tier"], p["tier"]),
            "State": _STATE.get(p["tier"], ""),
            "Severity": p.get("max_severity") or "",
            "Findings": p.get("finding_count") or 0,
        } for p in sorted(observed, key=lambda x: -(x.get("finding_count") or 0))]),
            use_container_width=True, hide_index=True)
    else:
        st.caption("No *observed* provider currently hits an inherited block.")

    # Full inherited blocklist policy (rules, not observations).
    policy_rows = [("🔴 Giggso baseline", g) for g in sorted(eff.giggso_deny)]
    if scope in ("project", "user"):
        policy_rows += [("🔴 Org deny", g) for g in sorted(eff.org_deny)]
    if scope == "user":
        policy_rows += [("🔴 Project deny", g) for g in sorted(eff.project_deny)]
    if policy_rows:
        with st.expander(f"Full inherited blocklist policy ({len(policy_rows)} rule(s))",
                         expanded=False):
            st.dataframe(pd.DataFrame(
                [{"Blocked by": src, "Pattern": pat} for src, pat in policy_rows]),
                use_container_width=True, hide_index=True)


def _current_lists(s, actor, org_id, scope, project_id, user_id) -> None:
    """The editable this-scope lists. Each entry can be removed OR flipped to
    the other list (allow<->block). Flipping a Giggso-baseline provider to
    allowed is routed through the guarded override (needs a reason)."""
    from db.models_policy import ApprovedTool, BlacklistedTool
    st.markdown(f"**This `{scope}` list** — allow / block set here")
    _list_block(s, actor, org_id, scope, project_id, user_id, "allowed",
                ApprovedTool, "domain_pattern")
    _list_block(s, actor, org_id, scope, project_id, user_id, "blocked",
                BlacklistedTool, "domain")


def _list_block(s, actor, org_id, scope, project_id, user_id, word, model, attr) -> None:
    from db.governance_crud import (
        list_scope, remove_entry, move_to_allowed, move_to_blocked,
    )
    rows = list_scope(s, model, org_id=org_id, scope=scope,
                      project_id=project_id, user_id=user_id)
    st.caption(f"{word.title()}: {len(rows)}")
    if not rows:
        return
    is_allow = word == "allowed"
    # Columns tailored per model — no redundant Name (== pattern) column.
    if is_allow:
        df = pd.DataFrame([{
            "Pattern": r.domain_pattern,
            "Expires": str(getattr(r, "valid_until", None) or ""),
            "Overrides Giggso": bool(getattr(r, "overrides_giggso", False)),
        } for r in rows])
    else:
        df = pd.DataFrame([{
            "Pattern": r.domain,
            "Severity": getattr(r, "severity", "") or "",
        } for r in rows])
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Unique label per row (pattern + short id) so selection is unambiguous.
    id_by_label = {f"{getattr(r, attr)}  ({str(r.id)[:6]})": r.id for r in rows}
    key = "ap" if is_allow else "dn"
    picked = st.multiselect(f"Select {word} entries", list(id_by_label),
                            key=f"sel::{scope}::{key}")
    flip_label = "→ Block selected" if is_allow else "→ Allow selected"
    reason = ""
    if not is_allow:
        reason = st.text_input(
            "Reason (required only for Giggso-baseline providers)",
            key=f"mvreason::{scope}::{key}",
            help="Flipping a Giggso-baseline tool to allowed is an audited "
                 "override — it needs a reason and gets a 90-day expiry.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button(flip_label, key=f"flip::{scope}::{key}") and picked:
            try:
                n_over = 0
                for lbl in picked:
                    if is_allow:
                        move_to_blocked(s, actor=actor, org_id=org_id,
                                        approve_row_id=id_by_label[lbl])
                    else:
                        if move_to_allowed(s, actor=actor, org_id=org_id,
                                            block_row_id=id_by_label[lbl],
                                            reason=reason.strip() or None):
                            n_over += 1
                extra = f" ({n_over} via guarded override)" if n_over else ""
                dest = "blocked" if is_allow else "allowed"
                _flash_and_rerun(f"Moved {len(picked)} entry(s) to {dest}{extra}.")
            except Exception as e:
                st.error(str(e))
    with c2:
        if st.button("Remove selected", key=f"rmb::{scope}::{key}") and picked:
            try:
                for lbl in picked:
                    remove_entry(s, actor=actor, model=model, row_id=id_by_label[lbl])
                _flash_and_rerun(f"Removed {len(picked)} entry(s) from {scope} {word}.")
            except Exception as e:
                st.error(str(e))


def _override_section(s, actor, org_id, is_admin, scope, project_id, user_id, providers) -> None:
    """Grant a Giggso-baseline override at the CURRENT scope (org/project/user).
    Org-admin only (enforced server-side). Weight: org ×0.5 / project ×0.6 /
    user ×0.7, band-floored ≥ MEDIUM."""
    import datetime as _dt
    if not is_admin:
        return
    blocked = [p for p in providers if p["tier"] == "giggso_deny"]
    if not blocked:
        return
    from db.governance_crud import add_approved
    weight = {"org": "×0.5", "project": "×0.6", "user": "×0.7"}.get(scope, "×0.5")
    with st.expander(f"🟠 Override Giggso baseline at {scope} scope "
                     f"({len(blocked)} blocked) — audited, {weight}, 90-day expiry"):
        if scope != "org" and not (project_id or user_id):
            st.caption("Pick a project/user above first."); return
        st.caption(f"Permits a Giggso-blocked tool at **{scope}** scope. Stays visible; "
                   "can never pull a device below MEDIUM (C2). Org-admin only, audited.")
        prov = st.selectbox("Blocked provider", [p["provider"] for p in blocked], key="ov_prov")
        reason = st.text_input("Reason (required)", key="ov_reason")
        if st.button(f"Override ({scope})", key="ov_btn"):
            if not reason.strip():
                st.error("A reason is required (C3)."); return
            try:
                add_approved(s, actor=actor, org_id=org_id, scope=scope,
                             project_id=project_id, user_id=user_id, name=prov,
                             provider_pattern=prov, overrides_giggso=True, reason=reason,
                             valid_until=_dt.date.today() + _dt.timedelta(days=90))
                _flash_and_rerun(f"Override recorded for `{prov}` at {scope} scope "
                                 f"({weight}, expires 90d).")
            except Exception as e:
                st.error(str(e))


# ── CSV mode (no DB) ──────────────────────────────────────────────────

def _render_csv(is_admin, email, nf) -> None:
    st.markdown(f"**Newly Found** — {len(nf)} provider(s) on no list yet")
    if not nf:
        st.success("Every observed provider is classified."); return
    if not is_admin:
        st.caption("Admin access is required to allow or block providers.")
        st.dataframe(pd.DataFrame([{"Provider": p["provider"], "Severity": p["max_severity"],
                                    "Findings": p["finding_count"]} for p in nf]),
                     use_container_width=True, hide_index=True)
        return
    for p in nf[:50]:
        c1, c2, c3 = st.columns([4, 1, 1])
        c1.write(f"`{p['provider']}` · {p['max_severity']} · {p['finding_count']} finding(s)")
        if c2.button("Allow", key=f"cal::{p['provider']}"):
            _csv_write(_ALLOW_KEY, _ALLOW_COLS,
                       {"name": p["provider"], "domain_pattern": p["provider"], "notes": "Provider Governance"},
                       email, "allowlist.governance", "domain_pattern", f"Allowed {p['provider']}")
        if c3.button("Block", key=f"cbl::{p['provider']}"):
            _csv_write(_DENY_KEY, _DENY_COLS,
                       {"name": f"Blocked {p['provider']}", "category": (p["category"] or "AI Tool"),
                        "domain": p["provider"], "port": "", "severity": (p["max_severity"] or "HIGH"),
                        "notes": "Provider Governance"},
                       email, "denylist.governance", "domain", f"Blocked {p['provider']}")


def _csv_write(key, cols, newrow, email, audit_field, dedup_on, msg) -> None:
    try:
        df = _io.read_csv_df(key, cols)
        merged = pd.concat([df, pd.DataFrame([newrow])], ignore_index=True)
        if dedup_on in merged.columns:
            merged = merged.drop_duplicates(subset=[dedup_on], keep="last")
        _io.put_csv(key, merged.to_csv(index=False), email, audit_field, len(df), len(merged), False)
        st.session_state["gov_flash"] = msg
        st.session_state.pop("policy_ctx_org", None)
        st.rerun()
    except Exception as exc:
        st.error(f"Action failed: {exc}")
