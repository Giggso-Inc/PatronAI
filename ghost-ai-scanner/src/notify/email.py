# =============================================================
# FILE: src/notify/email.py
# VERSION: 2.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Single home for ALL outbound email. Switched from AWS SES
#          to plain SMTP (smtplib) — no boto3 dependency, no AWS IAM
#          requirements, no per-recipient sandbox verification dance.
#
# Public surface (unchanged from v1):
#    send(recipient, subject, body, *, auto_verify=True)
#    send_welcome(recipient, name, role, added_by, company)
#    send_agent_otp(recipient, name, otp, installer_url, company)
#    send_alert(recipients, events)
#    ensure_verified(recipient, region=None)   ← no-op stub (SMTP needs none)
#
# Required env vars:
#    SMTP_HOST      — e.g. smtp.gmail.com / smtp.office365.com
#    SMTP_USERNAME  — login username (usually the sender address)
#    SMTP_PASSWORD  — login password or app password
#
# Optional env vars:
#    SMTP_PORT        — default 587 (STARTTLS). Use 465 for SSL.
#    SMTP_FROM_EMAIL  — display From address; falls back to SMTP_USERNAME
#    SMTP_USE_TLS     — "true" (default) / "false" to disable STARTTLS
#    SMTP_USE_SSL     — "true" to use SMTP_SSL (port 465); overrides TLS
#    COMPANY_NAME     — shown in email bodies (default "PatronAI")
#    PATRONAI_DASHBOARD_URL — link in welcome emails
#
# AUDIT LOG:
#   v1.0.0  2026-05-02  Initial. Consolidates three duplicated SES paths.
#   v2.0.0  2026-09-02  Switch from AWS SES to plain SMTP (smtplib).
#                       Public API unchanged. Removes boto3 dependency
#                       and SES recipient-verification requirement.
# =============================================================

from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText
from typing import Optional, Sequence

log = logging.getLogger("patronai.notify.email")


# ── Internal helpers ─────────────────────────────────────────────


def _smtp_cfg() -> dict:
    """Read SMTP config from environment. Raises RuntimeError if host missing."""
    host = (os.environ.get("SMTP_HOST") or "").strip()
    if not host:
        raise RuntimeError(
            "SMTP_HOST is not set — outbound email is unavailable. "
            "Set SMTP_HOST, SMTP_USERNAME, and SMTP_PASSWORD."
        )
    return {
        "host":     host,
        "port":     int(os.environ.get("SMTP_PORT") or "587"),
        "username": (os.environ.get("SMTP_USERNAME") or "").strip(),
        "password": (os.environ.get("SMTP_PASSWORD") or "").strip(),
        "use_ssl":  (os.environ.get("SMTP_USE_SSL") or "").strip().lower() == "true",
        "use_tls":  (os.environ.get("SMTP_USE_TLS") or "true").strip().lower() != "false",
    }


def _smtp_sender(company: str = "") -> str:
    """Resolve the From address.

    Priority:
      1. SMTP_FROM_EMAIL — explicit display address.
      2. SMTP_USERNAME   — the login is also the sender in most setups.
      3. patronai@<company>.com — last-resort fallback; logs a WARN.
    """
    addr = (os.environ.get("SMTP_FROM_EMAIL") or "").strip()
    if addr:
        return addr
    username = (os.environ.get("SMTP_USERNAME") or "").strip()
    if username:
        return username
    co = company or os.environ.get("COMPANY_NAME", "PatronAI")
    fallback = f"patronai@{co.lower()}.com"
    log.warning("SMTP_FROM_EMAIL and SMTP_USERNAME not set; "
                "using fallback sender %s", fallback)
    return fallback


# ── Recipient verification (no-op for SMTP) ──────────────────────


def ensure_verified(recipient: str,
                     region: Optional[str] = None) -> dict:
    """No-op stub — SMTP has no per-recipient verification requirement.
    Kept so callers written for SES don't need to change."""
    addr = (recipient or "").strip()
    return {"action": "already_verified", "status": "n/a",
            "recipient": addr, "region": region or ""}


# ── Generic send (single SMTP call site) ─────────────────────────


def send(recipient,
         subject: str,
         body: str,
         *,
         company: str = "",
         auto_verify: bool = True) -> bool:
    """Send a plain-text email via SMTP.

    Args:
        recipient:    A single address (str) or list/tuple of addresses.
        subject:      Subject line.
        body:         Plain-text body.
        company:      Optional company name; influences sender fallback.
        auto_verify:  Accepted for API compatibility — ignored (SMTP
                      needs no recipient pre-verification).

    Returns:
        True on success, False on any config or connection error.
    """
    if isinstance(recipient, str):
        recipients: list = [recipient]
    else:
        recipients = [r.strip() for r in recipient if r and str(r).strip()]
    if not recipients:
        log.error("send: no recipients")
        return False

    try:
        cfg    = _smtp_cfg()
        sender = _smtp_sender(company)

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"]    = sender
        msg["To"]      = ", ".join(recipients)

        if cfg["use_ssl"]:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"]) as conn:
                if cfg["username"]:
                    conn.login(cfg["username"], cfg["password"])
                conn.sendmail(sender, recipients, msg.as_string())
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"]) as conn:
                if cfg["use_tls"]:
                    conn.starttls()
                if cfg["username"]:
                    conn.login(cfg["username"], cfg["password"])
                conn.sendmail(sender, recipients, msg.as_string())

        log.info("notify.email.send → %s (subject=%r, sender=%s, "
                 "host=%s)", recipients, subject[:60], sender, cfg["host"])
        return True
    except Exception as exc:
        log.error("notify.email.send failed → %s — %s: %s",
                  recipients, type(exc).__name__, exc)
        return False


# ── Convenience wrappers — one per business domain ──────────────


def send_welcome(recipient: str, name: str, role: str,
                  added_by: str, company: str = "") -> bool:
    """Welcome / onboarding email when an admin adds a user.

    Body explains role + dashboard URL + warns about the separate
    AWS verification email the recipient may receive.
    """
    company  = company or os.environ.get("COMPANY_NAME", "PatronAI")
    dash_url = os.environ.get("PATRONAI_DASHBOARD_URL",
                                "https://your-patronai-dashboard")
    subject = f"Welcome to PatronAI — {company}"
    body = (
        f"Hi {name},\n\n"
        f"You have been added to the PatronAI security dashboard "
        f"for {company}.\n\n"
        f"  Role:      {role}\n"
        f"  Added by:  {added_by}\n\n"
        f"Log in here:\n"
        f"  {dash_url}\n\n"
        f"PatronAI monitors AI tool usage across your organisation "
        f"and surfaces security findings for your team.\n\n"
        f"If you have questions, reply to this email or contact "
        f"your administrator ({added_by}).\n\n"
        f"— PatronAI · {company}\n"
    )
    return send(recipient, subject, body, company=company)


def send_agent_otp(recipient: str, name: str, otp: str,
                    installer_url: str, company: str = "") -> bool:
    """Agent-installer OTP + download link, sent when an admin
    generates a deploy package."""
    company = company or os.environ.get("COMPANY_NAME", "PatronAI")
    subject = "PatronAI Agent — Your Installation Package"
    body = (
        f"Hi {name},\n\n"
        f"Your PatronAI agent installer is ready.\n\n"
        f"Download link (expires in 48 hours):\n{installer_url}\n\n"
        f"Your one-time installation code:\n\n"
        f"    {otp}\n\n"
        f"To install:\n"
        f"  Mac/Linux: bash setup_agent.sh\n"
        f"  Windows:   powershell -ExecutionPolicy Bypass -File setup_agent.ps1\n\n"
        f"Enter the 6-digit code when prompted. It is single-use and "
        f"expires in 48 hours.\n\n"
        f"Your IT admin can also provide a one-click DMG (Mac) or EXE "
        f"(Windows).\n\n"
        f"Questions? Contact your IT administrator.\n\n"
        f"— PatronAI · {company}\n"
    )
    return send(recipient, subject, body, company=company)


def send_alert(recipients,
                events: Sequence[dict]) -> bool:
    """On-demand action-item alert. Bulleted summary of N selected
    findings sent to one or more recipients (typically ALERT_RECIPIENTS).

    Time formatting deliberately deferred to dashboard.ui.time_fmt so
    every email shows timestamps in the operator's local zone.
    """
    if not events:
        log.warning("send_alert: empty events list, nothing to send")
        return False

    # Build the body. Imports here so a missing dashboard package
    # (e.g. when notify.email is used from a CLI script) doesn't crash.
    try:
        from time_fmt import fmt as _fmt_time  # type: ignore
    except Exception:  # pragma: no cover — fall back to raw timestamp
        def _fmt_time(x):  # type: ignore
            return x or ""

    n = len(events)
    body_lines = [f"PatronAI Alert — {n} event(s) require attention\n"]
    for e in events[:10]:
        body_lines.append(
            f"  [{e.get('severity','?')}] {e.get('provider','?')} | "
            f"{e.get('owner','unknown')} | {_fmt_time(e.get('timestamp'))}"
        )
    if n > 10:
        body_lines.append(f"  … and {n - 10} more.")
    body = "\n".join(body_lines)

    if isinstance(recipients, str):
        # Accept comma-separated string for backwards compat.
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]
    return send(list(recipients), f"PatronAI Alert — {n} event(s)", body)
