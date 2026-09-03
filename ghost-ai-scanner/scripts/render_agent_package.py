# =============================================================
# FILE: scripts/render_agent_package.py
# VERSION: 1.6.0
# UPDATED: 2026-04-27
# OWNER: Giggso Inc
# PURPOSE: Main entry point for generating an agent delivery package.
#          Orchestrates: OTP generation → template render → S3 upload
#          → presigned URLs → SES email → DMG + EXE build on EC2.
#          Callable from Streamlit or CLI.
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial — agent delivery system
#   v1.1.0  2026-04-19  S3 prefix agents/ → config/HOOK_AGENTS/; DMG builder
#   v1.2.0  2026-04-19  HEARTBEAT_PUT_URL template placeholder (7-day liveness)
#   v1.3.0  2026-04-20  EC2-side builders — always render sh + ps1, build DMG
#                       and EXE on EC2 via genisoimage / makensis.
#   v1.4.0  2026-04-20  authorized_domains per-user whitelist; SCAN_PUT_URL for
#                       endpoint package/process/browser-history scan results.
#   v1.5.0  2026-04-25  Group 2 — concatenate scan_*.py.frag files into the
#                       INLINE_SCAN_PYTHON placeholder. Templates become thin
#                       orchestrators; scan logic lives in fragments.
#   v1.5.1  2026-04-25  Fix: store.agent.write_url_bundle → store.write_url_bundle.
#   v1.6.0  2026-04-27  Render uninstall_agent.sh/.ps1 and store alongside installer.
#   v1.6.1  2026-07-23  Fix: encode .ps1 uploads as utf-8-sig (BOM). Windows
#                       PowerShell 5.1 has no BOM => falls back to the
#                       system ANSI codepage, misreading the em-dashes in
#                       Write-Info messages; one resulting byte decodes to
#                       a Unicode smart-quote that PowerShell's tokenizer
#                       treats as a string terminator, corrupting the rest
#                       of the parse. .sh stays plain utf-8 — a BOM there
#                       would break shebang detection on Linux/Mac.
#   v1.7.0  2026-09-01  enable_packetbeat param -> {{ENABLE_PACKETBEAT}}
#                       placeholder. Previously the installer templates
#                       read a bare $env:PATRONAI_ENABLE_PACKETBEAT /
#                       ${PATRONAI_ENABLE_PACKETBEAT:-} that was never set
#                       by anything in this pipeline, so Packetbeat was
#                       silently skipped for every recipient regardless of
#                       intent. Now it's a real per-recipient decision
#                       baked into the rendered script, same as
#                       authorized_domains. Defaults to False (unchanged
#                       behaviour for existing callers).
# =============================================================

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from build_agent_artifacts import _build_macos_dmg, _build_windows_exe
from scan_fragment_loader  import load_scan_fragments

log = logging.getLogger("marauder-scan.render_agent")

HOOK_AGENTS_PREFIX       = "config/HOOK_AGENTS"
TEMPLATE_DIR             = Path(__file__).parent.parent / "agent" / "install"
SH_TEMPLATE              = TEMPLATE_DIR / "setup_agent.sh.template"
PS1_TEMPLATE             = TEMPLATE_DIR / "setup_agent.ps1.template"
UNINSTALL_SH_TEMPLATE    = TEMPLATE_DIR / "uninstall_agent.sh.template"
UNINSTALL_PS1_TEMPLATE   = TEMPLATE_DIR / "uninstall_agent.ps1.template"



# ── Capture companion payload ────────────────────────────────────────────
# The companion ships as 5 real .py files. Bundling them into the single
# scan-agent installer means embedding them, and they are embedded BASE64,
# not as here-strings.
#
# That is not cosmetic. The device verifies these files at every startup
# against a server-side manifest of their sha256. A here-string round trip
# through PowerShell can normalise line endings or re-encode a non-ASCII
# byte; the file still "looks" right but its hash changes, and the
# companion then reports "code modified since install" and refuses to run.
# Base64 round-trips the exact bytes, so the hash the server published is
# the hash the device computes. The 33% size cost buys that guarantee.
#
# CAPTURE_FILES is the authoritative list and MUST match common.py's
# VERIFIED_FILES. Never glob *.py here: the source tree also holds dev-only
# harnesses, and a glob would ship them to every recipient.
CAPTURE_FILES = ["pktmon_to_jsonl.py", "common.py", "capture_service.py",
                 "sync_task.py", "uploader.py"]

# Pinned Wireshark 4.6.8 x64 NSIS installer. The .exe, not the .msi:
# msiexec rejects the /S switch the installer passes, and /S is also what
# makes Wireshark skip its bundled Npcap.
WIRESHARK_URL = ("https://2.na.dl.wireshark.org/win64/"
                 "Wireshark-4.6.8-x64.exe")



def _urls_json_for_capture(store, token: str) -> str:
    """The exact urls.json the device should carry, as a JSON string.

    Read back from the bundle we just wrote rather than re-minting: a second
    mint would produce DIFFERENT presigned signatures, so the installer would
    bake in URLs that are valid but not the ones the server recorded.
    """
    raw = store._get(f"config/HOOK_AGENTS/{token}/urls.json")
    return raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)



def _capture_files_literal(files_b64: dict, os_type: str) -> str:
    """Render the embedded file table in the syntax its template parses.

    Windows consumes a PowerShell hashtable body; the shells read
    "name|base64" lines from a quoted heredoc. Emitting the wrong one is
    silent - PowerShell would see garbage keys, and the shell loop would
    read nothing and write zero .py files, surfacing much later as an
    integrity mismatch rather than a parse error.
    """
    if os_type == "windows":
        return chr(10).join("    '%s' = '%s'" % (n, b) for n, b in files_b64.items())
    return chr(10).join("%s|%s" % (n, b) for n, b in files_b64.items())


def _capture_payload(token: str, company: str, urls_json: str,
                     os_type: str = "windows") -> dict:
    """Base64 payloads for the capture companion, plus the sha256 manifest
    computed over the SAME bytes that get embedded.

    Returning the manifest from here - rather than hashing the files again
    at the call site - is deliberate: two independent reads of the same
    files can disagree if one is edited mid-render, and the failure mode is
    a device that refuses to start.
    """
    import base64 as _b64
    import hashlib as _hl

    cap_dir = Path(__file__).resolve().parents[1] / "agent" / "capture"
    files_b64, manifest = {}, {}
    for name in CAPTURE_FILES:
        raw = (cap_dir / name).read_bytes()
        files_b64[name] = _b64.b64encode(raw).decode("ascii")
        manifest[name] = _hl.sha256(raw).hexdigest()

    # The capture installer is itself a template. Render it here so the
    # device never sees an unsubstituted placeholder, then embed it the
    # same way.
    # One installer per OS. linux has no WIRESHARK_URL placeholder (it takes
    # tshark from the distro package manager); replace() on a key the file
    # does not contain is a harmless no-op, so one map serves all three.
    inst_name = {"windows": "install-windows.ps1",
                 "mac":     "install-mac.sh",
                 "linux":   "install-linux.sh"}.get(os_type, "install-windows.ps1")
    inst = (cap_dir / "install" / inst_name).read_text(encoding="utf-8")
    for key, val in {
        "TOKEN":         token,
        "DEVICE_ID":     f"{token}-cap",
        "COMPANY":       company,
        "URLS_JSON":     urls_json,
        "WIRESHARK_URL":    WIRESHARK_URL,
    }.items():
        inst = inst.replace("{{%s}}" % key, val)

    # Guard, not a comment: an unsubstituted placeholder is invisible until
    # the device runs the script and fails. {{WIRESHARK_SHA256}} once shipped
    # exactly that way once - and the check that should have caught it used
    # the regex [A-Z_]+, which does not match the digits in "SHA256", so it
    # reported "no placeholders left" while one remained. Hence [A-Z0-9_]+.
    import re as _re
    left = _re.findall(r"[{]{2}[A-Z0-9_]+[}]{2}", inst)
    if left:
        raise RuntimeError(
            "capture installer still has unsubstituted placeholders: "
            + ", ".join(sorted(set(left))))

    return {
        "files_b64":     files_b64,
        "manifest":      manifest,
        "installer_b64": _b64.b64encode(inst.encode("utf-8")).decode("ascii"),
    }


def render_agent_package(
    recipient_name: str,
    recipient_email: str,
    os_type: str,
    store,
    renderer,
    send_email: bool = True,
    authorized_domains: list | None = None,
    otp_override: str | None = None,
    enable_packetbeat: bool = False,
    enable_capture: bool = False,
) -> dict:
    """
    Generate a complete agent delivery package.

    Always builds BOTH macOS DMG and Windows EXE on EC2.
    authorized_domains: per-user allowlist baked into the script.
      Scan findings matching these domains/packages are suppressed.
    enable_packetbeat: per-recipient decision, baked into the rendered
      script as PATRONAI_ENABLE_PACKETBEAT. Defaults to off — Packetbeat
      needs admin/root and its own Npcap driver install on Windows, so
      this should only be turned on for recipients where that's wanted.
    enable_capture: per-recipient decision for the tshark capture
      companion (PatronAI Capture / PatronAI Capture Sync). Defaults to
      off: it needs Administrator, installs Wireshark (~90 MB) and runs a
      boot service, so it is a much heavier ask than the scan agent. When
      off, the payload is still embedded in the script but never decoded
      or executed - gating at run time, not at render time, keeps ONE
      rendered artifact per recipient rather than two variants.
    otp_override: when set, use this string as the OTP instead of
      generating a new one — used by Raven-bundled invites so both
      products validate against the SAME OTP the user entered in
      Raven's installer. Standalone callers omit it and get the
      normal fresh-random OTP path.
    Returns dict with: token, otp, installer_url, meta_url,
    status_put_url, heartbeat_put_url, scan_put_url,
    dmg_url, exe_url, success, error.
    """
    if os_type not in ("mac", "linux", "windows"):
        return {"success": False, "error": f"Unsupported os_type: {os_type}"}
    if not SH_TEMPLATE.exists():
        return {"success": False, "error": f"Template not found: {SH_TEMPLATE}"}
    if not PS1_TEMPLATE.exists():
        return {"success": False, "error": f"Template not found: {PS1_TEMPLATE}"}

    try:
        # otp_override lets a trusted caller (Raven Hub) mirror its own OTP
        # into PatronAI's meta.json so the installer's bcrypt check
        # succeeds against the SAME OTP the user typed in Raven — no
        # weaker "trust flag" bypass required. Reject anything that
        # doesn't look like a 6-digit code before it lands in the hash.
        if otp_override is not None:
            if not (isinstance(otp_override, str) and otp_override.isdigit() and len(otp_override) == 6):
                return {"success": False, "error": "otp_override must be a 6-digit numeric string"}
            otp = otp_override
        else:
            otp = store.generate_otp()
        otp_hash = store.hash_otp(otp)
    except Exception as e:
        log.error("OTP generation failed: %s", e)
        return {"success": False, "error": f"OTP generation failed: {e}"}

    bucket  = store.bucket
    region  = store.region
    company = os.environ.get("COMPANY_NAME", "PatronAI")
    # Authorised domains as comma-separated string baked into the script
    auth_domains_str = ",".join(authorized_domains) if authorized_domains else ""

    try:
        from datetime import datetime, timezone, timedelta
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()

        # Concatenate scan fragments once — same Python is inlined in
        # both bash and PowerShell installer templates.
        inline_scan_python = load_scan_fragments(TEMPLATE_DIR)

        # THE shared device-side uploader (agent/shared/uploader.py). Read at
        # render time so the inlined copy can never drift from the file the
        # capture companion imports - one implementation, two delivery
        # mechanisms. This is what replaced `aws s3 cp`, which was AWS-only
        # and needed long-lived credentials on an employee laptop.
        uploader_source = (TEMPLATE_DIR.parent / "shared" / "uploader.py").read_text(
            encoding="utf-8")

        # Step 0 — recipient-side self-test scripts; baked into the installer
        # so a single artifact carries everything the recipient needs.
        diag_sh_path  = TEMPLATE_DIR / "diagnose.sh"
        diag_ps1_path = TEMPLATE_DIR / "diagnose.ps1"
        inline_diagnose_sh  = diag_sh_path.read_text(encoding="utf-8")  if diag_sh_path.exists()  else ""
        inline_diagnose_ps1 = diag_ps1_path.read_text(encoding="utf-8") if diag_ps1_path.exists() else ""

        # ── Pass 1: placeholder render to get token ───────────
        placeholder_ctx = {
            "RECIPIENT_NAME":      recipient_name,
            "RECIPIENT_EMAIL":     recipient_email,
            "BUCKET":              bucket,
            "REGION":              region,
            "COMPANY":             company,
            "TOKEN":               "PENDING",
            "EXPIRES_AT":          expires_at,
            "META_URL":            "PENDING",
            "STATUS_PUT_URL":      "PENDING",
            "HEARTBEAT_PUT_URL":   "PENDING",
            "SCAN_PUT_URL":        "PENDING",
            "AUTHORIZED_GET_URL":  "PENDING",
            "URLS_REFRESH_URL":    "PENDING",
            "AUTHORIZED_DOMAINS":  auth_domains_str,
            "ENABLE_PACKETBEAT":   "1" if enable_packetbeat else "0",
            "ENABLE_CAPTURE":      "0",
            "CAPTURE_FILES_B64":   "",
            "CAPTURE_INSTALLER_B64": "",
            "INLINE_SCAN_PYTHON":  inline_scan_python,
            "UPLOADER_SOURCE":     uploader_source,
            "INLINE_DIAGNOSE_SH":  inline_diagnose_sh,
            "INLINE_DIAGNOSE_PS1": inline_diagnose_ps1,
        }
        pre_sh = renderer.render(str(SH_TEMPLATE), placeholder_ctx)

        # create_package uploads sh, meta.json, status.json, authorized.csv → token
        token = store.create_package(
            recipient_name     = recipient_name,
            recipient_email    = recipient_email,
            os_type            = os_type,
            rendered_script    = pre_sh,
            otp_hash           = otp_hash,
            authorized_domains = authorized_domains or [],
        )
        if not token:
            return {"success": False, "error": "Failed to upload package to S3"}

        urls = store.get_presigned_urls(token, os_type)
        if not urls:
            return {"success": False, "error": "Failed to generate presigned URLs"}

        # Seed the first urls.json bundle so the laptop has refreshable URLs from minute 0.
        store.write_url_bundle(token, os_type)

        # ── Capture companion payload + its code manifest ─────
        # Built ONCE, from a single read of the files: the bytes that get
        # embedded in the installer are the bytes that get hashed here.
        # Hashing separately would let the two drift and brick the device.
        #
        # The manifest MUST be published even when enable_capture is False.
        # The URL bundle above always mints a `code_manifest_url`, and if
        # nothing ever writes to that key it 404s - which the companion's
        # integrity check cannot tell apart from tampering, so it fails
        # closed and refuses to start. That was the real state of dev:
        # every token had a code_manifest_url pointing at nothing.
        try:
            _cap_payload = _capture_payload(token, company,
                                            _urls_json_for_capture(store, token), os_type)
            if not store.write_code_manifest(token, _cap_payload["manifest"]):
                log.warning("code manifest publish failed for %s - a capture "
                            "install on this token will refuse to start", token)
        except Exception as exc:
            log.warning("capture payload skipped (%s) - capture installs on "
                        "token %s will refuse to start", exc, token)
            _cap_payload = {"files_b64": {}, "manifest": {}, "installer_b64": ""}

        # ── Pass 2: re-render both templates with real URLs ───
        final_ctx = {
            "RECIPIENT_NAME":     recipient_name,
            "RECIPIENT_EMAIL":    recipient_email,
            "BUCKET":             bucket,
            "REGION":             region,
            "COMPANY":            company,
            "TOKEN":              token,
            "EXPIRES_AT":         expires_at,
            "META_URL":           urls["meta_url"],
            "STATUS_PUT_URL":     urls["status_put_url"],
            "HEARTBEAT_PUT_URL":  urls.get("heartbeat_put_url", ""),
            "SCAN_PUT_URL":       urls.get("scan_put_url", ""),
            "AUTHORIZED_GET_URL": urls.get("authorized_get_url", ""),
            "URLS_REFRESH_URL":   urls.get("urls_refresh_url", ""),
            "AUTHORIZED_DOMAINS": auth_domains_str,  # fallback if URL unreachable
            "ENABLE_PACKETBEAT":  "1" if enable_packetbeat else "0",
            "ENABLE_CAPTURE":     "1" if enable_capture else "0",
            # A PowerShell hashtable literal, name -> base64. Built here
            # rather than in the template so the template stays a template.
            "CAPTURE_FILES_B64":  _capture_files_literal(
                _cap_payload["files_b64"], os_type),
            "CAPTURE_INSTALLER_B64": _cap_payload["installer_b64"],
            "INLINE_SCAN_PYTHON": inline_scan_python,
            "UPLOADER_SOURCE":    uploader_source,
            "INLINE_DIAGNOSE_SH":  inline_diagnose_sh,
            "INLINE_DIAGNOSE_PS1": inline_diagnose_ps1,
        }
        sh_script  = renderer.render(str(SH_TEMPLATE),  final_ctx)
        ps1_script = renderer.render(str(PS1_TEMPLATE), final_ctx)

        # Overwrite sh; upload ps1 alongside it.
        # ps1 uses utf-8-sig (BOM) — Windows PowerShell 5.1 has no other way
        # to know a script file is UTF-8, and without it the em-dashes in
        # Write-Info messages get misread as the system ANSI codepage,
        # corrupting the parse (see v1.6.1 changelog above). sh must stay
        # plain utf-8 — a BOM there breaks shebang detection on Linux/Mac.
        store._put(f"{HOOK_AGENTS_PREFIX}/{token}/setup_agent.sh",
                   sh_script.encode(),  "text/plain")
        store._put(f"{HOOK_AGENTS_PREFIX}/{token}/setup_agent.ps1",
                   ps1_script.encode("utf-8-sig"), "text/plain")

        # Render and store personalised uninstall scripts (token baked in)
        uninstall_ctx = {
            "RECIPIENT_NAME":  recipient_name,
            "RECIPIENT_EMAIL": recipient_email,
            "COMPANY":         company,
            "TOKEN":           token,
            "EXPIRES_AT":      expires_at,
        }
        if UNINSTALL_SH_TEMPLATE.exists():
            uninstall_sh = renderer.render(str(UNINSTALL_SH_TEMPLATE), uninstall_ctx)
            store._put(f"{HOOK_AGENTS_PREFIX}/{token}/uninstall_agent.sh",
                       uninstall_sh.encode(), "text/plain")
        if UNINSTALL_PS1_TEMPLATE.exists():
            uninstall_ps1 = renderer.render(str(UNINSTALL_PS1_TEMPLATE), uninstall_ctx)
            store._put(f"{HOOK_AGENTS_PREFIX}/{token}/uninstall_agent.ps1",
                       uninstall_ps1.encode("utf-8-sig"), "text/plain")

    except Exception as e:
        log.error("Package generation failed: %s", e)
        return {"success": False, "error": str(e)}

    # ── EC2-side artifact builds ──────────────────────────────
    dmg_key = _build_macos_dmg(sh_script,  recipient_name, token, store)
    exe_key = _build_windows_exe(ps1_script, recipient_name, token, store)

    dmg_url = store.get_artifact_url(dmg_key) if dmg_key else ""
    exe_url = store.get_artifact_url(exe_key) if exe_key else ""

    result = {
        "success":            True,
        "token":              token,
        "otp":                otp,
        "installer_url":      urls["installer_url"],
        "meta_url":           urls["meta_url"],
        "status_put_url":     urls["status_put_url"],
        "heartbeat_put_url":  urls.get("heartbeat_put_url", ""),
        "scan_put_url":       urls.get("scan_put_url", ""),
        "authorized_domains": authorized_domains or [],
        "dmg_url":            dmg_url,
        "exe_url":            exe_url,
    }

    if send_email:
        result["email_sent"] = _send_email(
            recipient_name, recipient_email, otp,
            urls["installer_url"], company
        )

    return result


def _send_email(
    recipient_name: str,
    recipient_email: str,
    otp: str,
    installer_url: str,
    company: str,
) -> bool:
    """Thin shim: delegates to notify.email.send_agent_otp.

    Kept as a private function in this module so existing callers
    don't move; all SES logic (sender resolution, region, recipient
    verification, error logging) lives in src/notify/email.py.
    """
    from notify.email import send_agent_otp
    return send_agent_otp(recipient=recipient_email,
                          name=recipient_name,
                          otp=otp,
                          installer_url=installer_url,
                          company=company)
