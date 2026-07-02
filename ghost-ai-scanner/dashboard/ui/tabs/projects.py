# =============================================================
# FILE: dashboard/ui/tabs/projects.py
# VERSION: 1.0.0
# UPDATED: 2026-06-30
# OWNER: Giggso Inc
# PURPOSE: Projects management tab (Phase F4, ADR_2026-06-29). Org-admin only.
#          Create projects and add/remove members, backed by Postgres
#          (projects / project_members). Drives project-scope policy. CRUD + authz
#          live in db.governance_crud (tested); this is the render layer.
# DEPENDS: streamlit, db.* (requires DATABASE_URL)
# =============================================================

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))


def render(is_admin: bool, email: str = "") -> None:
    if not os.environ.get("DATABASE_URL"):
        st.info("Projects require the policy database (set DATABASE_URL).")
        return
    if not is_admin:
        st.info("Project management is admin-only.")
        return
    try:
        from db.engine import get_session
        from db.policy_queries import get_identity
        with get_session() as s:
            actor, org_id, _ = get_identity(s, email)
            if actor is None or org_id is None:
                st.warning(f"'{email}' isn't a policy-DB user yet — re-open the dashboard "
                           "so the one-time seed runs, or seed the DB first.")
                return
            _render(s, actor, org_id)
    except Exception as exc:
        st.error(f"Projects unavailable: {exc}")


def _render(s, actor, org_id) -> None:
    from db.governance_crud import (
        add_project_member, create_project, list_org_users, list_project_members,
        list_projects, remove_project_member,
    )
    st.markdown("**Projects** — group members so policy can be scoped per project.")

    with st.form("create_project", clear_on_submit=True):
        c1, c2 = st.columns(2)
        slug = c1.text_input("Project slug", placeholder="engineering")
        name = c2.text_input("Display name", placeholder="Engineering")
        if st.form_submit_button("Create project") and slug and name:
            try:
                create_project(s, actor=actor, org_id=org_id, slug=slug, display_name=name)
                st.success(f"Project '{name}' created."); st.rerun()
            except Exception as exc:
                st.error(str(exc))

    projects = list_projects(s, org_id)
    users = list_org_users(s, org_id)
    if not projects:
        st.caption("No projects yet — create one above.")
        return

    for project, count in projects:
        with st.expander(f"{project.display_name}  ·  {count} member(s)"):
            members = list_project_members(s, project.id)
            for m in members:
                c1, c2 = st.columns([4, 1])
                c1.write(m.email)
                if c2.button("Remove", key=f"rm::{project.id}::{m.id}"):
                    remove_project_member(s, actor=actor, project_id=project.id, user_id=m.id)
                    st.rerun()
            member_ids = {m.id for m in members}
            addable = [u for u in users if u.id not in member_ids]
            if addable:
                pick = st.selectbox("Add member", addable,
                                    format_func=lambda u: u.email,
                                    key=f"pick::{project.id}")
                if st.button("Add", key=f"add::{project.id}") and pick is not None:
                    add_project_member(s, actor=actor, project_id=project.id, user_id=pick.id)
                    st.rerun()
