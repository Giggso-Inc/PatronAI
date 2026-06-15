# =============================================================
# FILE: src/notify/email.py
# VERSION: 2.0.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Single home for ALL outbound email via OCI Email Delivery.
#          OCI migration: replaced AWS SES with OCI Email Delivery
#          SMTP relay. OCI Email Delivery is SMTP-compatible — uses
#          Python smtplib, no SDK needed.
#
# Public surface (unchanged from v1.0.0):
#    send(recipient, subject, body, *, auto_verify=True)
#    send_welcome(recipient, name, role, added_by, company)
#    send_agent_otp(recipient, name, otp, installer_url, company)
#    send_alert(recipients, events)
#    ensure_verified(recipient, region=None)
#
# OCI Email Delivery SMTP settings:
#    SMTP endpoint: smtp.email.<region>.oci.oraclecloud.com:587
#    Auth:          OCI Email Delivery SMTP credentials
#    Env vars:      OCI_EMAIL_SMTP_USER, OCI_EMAIL_SMTP_PASSWORD
#                   (generated in OCI Console → Email Delivery → SMTP Credentials)
#
# DEPENDS: smtplib (stdlib), env vars OCI_EMAIL_SMTP_USER /
#          OCI_EMAIL_SMTP_PASSWORD / PATRONAI_FROM_EMAIL /
#          COMPANY_NAME / AWS_REGION (holds OCI region)
# AUDIT LOG:
#   v1.0.0  2026-05-02  Initial (AWS SES via boto3)
#   v2.0.0  2026-06-11  OCI migration — replaced boto3 SES with
#                       OCI Email Delivery SMTP relay (smtplib).
#                       ensure_verified() is no-op on OCI
#                       (OCI Email Delivery handles verification differently).
#                       All public function signatures unchanged.
# =============================================================

from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Iterable, Optional, Sequence

log = logging.getLogger("patronai.notify.email")


# ── Internal helpers ─────────────────────────────────────────────


def _oci_region() -> str:
    """OCI region from AWS_REGION env var (boto3 variable name, stores OCI region)."""
    return os.environ.get("AWS_REGION", "us-chicago-1")


def _smtp_host() -> str:
    """OCI Email Delivery SMTP endpoint for the configured region."""
    region = _oci_region()
    return f"smtp.email.{region}.oci.oraclecloud.com"


def _smtp_port() -> int:
    """OCI Email Delivery SMTP port (587 = STARTTLS)."""
    return int(os.environ.get("OCI_EMAIL_SMTP_PORT", "587"))


def _smtp_credentials() -> tuple:
    """
    Return (username, password) for OCI Email Delivery SMTP.
    Generate in OCI Console → Email Delivery → SMTP Credentials.
    """
    user = os.environ.get("OCI_EMAIL_SMTP_USER", "")
    password = os.environ.get("OCI_EMAIL_SMTP_PASSWORD", "")
    return user, password


def _email_sender(company: str = "") -> str:
    """
    Resolve the From address.
    Priority:
      1. PATRONAI_FROM_EMAIL
      2. patronai@<company>.com fallback
    """
    sender = os.environ.get("PATRONAI_FROM_EMAIL", "")
    if sender:
        return sender
    co = company or os.environ.get("COMPANY_NAME", "PatronAI")
    fallback = f"patronai@{co.lower()}.com"
    log.warning(
        "PATRONAI_FROM_EMAIL not set; using fallback %s — "
        "verify this address in OCI Email Delivery", fallback
    )
    return fallback


# ── Recipient verification ──────────────────────────────────────


def ensure_verified(recipient: str, region: Optional[str] = None) -> dict:
    """
    OCI Email Delivery handles sender domain verification via SPF/DKIM.
    Recipient verification is NOT required on OCI (unlike AWS SES sandbox).
    This function is a no-op on OCI — returns 'already_verified' for
    backwards compatibility with callers that check the return value.
    """
    addr = (recipient or "").strip()
    return {
        "action":    "already_verified",
        "status":    "OCI_no_verification_required",
        "recipient": addr,
        "region":    region or _oci_region(),
    }


# ── Generic send (single SMTP call site) ────────────────────────


def send(
    recipient,
    subject: str,
    body: str,
    *,
    company: str = "",
    auto_verify: bool = True,  # no-op on OCI, kept for API compat
) -> bool:
    """
    Send a plain-text email via OCI Email Delivery SMTP.
    Single SMTP call site for the whole codebase.

    Args:
        recipient:    A single address (str) or an iterable of addresses.
        subject:      Subject line.
        body:         Plain-text body.
        company:      Optional company name; influences sender fallback.
        auto_verify:  No-op on OCI (kept for API backwards compatibility).

    Returns:
        True on success, False on any SMTP / config error.
    """
    sender = _email_sender(company)

    if isinstance(recipient, str):
        recipients: list = [recipient]
    else:
        recipients = [r.strip() for r in recipient if r and str(r).strip()]
    if not recipients:
        log.error("send: no recipients")
        return False

    smtp_user, smtp_pass = _smtp_credentials()
    if not smtp_user or not smtp_pass:
        log.error(
            "OCI Email Delivery SMTP credentials not set. "
            "Set OCI_EMAIL_SMTP_USER and OCI_EMAIL_SMTP_PASSWORD in .env. "
            "Generate at: OCI Console → Email Delivery → SMTP Credentials"
        )
        return False

    try:
        msg = MIMEMultipart()
        msg["From"]    = sender
        msg["To"]      = ", ".join(recipients)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(_smtp_host(), _smtp_port()) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(smtp_user, smtp_pass)
            smtp.sendmail(sender, recipients, msg.as_string())

        log.info(
            "notify.email.send → %s (subject=%r, sender=%s, region=%s)",
            recipients, subject[:60], sender, _oci_region()
        )
        return True

    except smtplib.SMTPAuthenticationError:
        log.error(
            "OCI Email Delivery SMTP auth failed — check OCI_EMAIL_SMTP_USER "
            "and OCI_EMAIL_SMTP_PASSWORD in .env"
        )
        return False
    except Exception as exc:
        log.error(
            "notify.email.send failed → %s — sender=%s region=%s message=%s",
            recipients, sender, _oci_region(), exc
        )
        return False


# ── Convenience wrappers ─────────────────────────────────────────


def send_welcome(
    recipient: str, name: str, role: str,
    added_by: str, company: str = ""
) -> bool:
    """Welcome / onboarding email when an admin adds a user."""
    company  = company or os.environ.get("COMPANY_NAME", "PatronAI")
    dash_url = os.environ.get("PATRONAI_DASHBOARD_URL", "https://patronai.giggso.com")
    subject  = f"Welcome to PatronAI — {company}"
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


def send_agent_otp(
    recipient: str, name: str, otp: str,
    installer_url: str, company: str = ""
) -> bool:
    """Agent-installer OTP + download link."""
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
        f"Questions? Contact your IT administrator.\n\n"
        f"— PatronAI · {company}\n"
    )
    return send(recipient, subject, body, company=company)


def send_alert(recipients, events: Sequence[dict]) -> bool:
    """On-demand action-item alert. Bulleted summary of N selected findings."""
    if not events:
        log.warning("send_alert: empty events list, nothing to send")
        return False

    try:
        from time_fmt import fmt as _fmt_time  # type: ignore
    except Exception:
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
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]
    return send(list(recipients), f"PatronAI Alert — {n} event(s)", body)
