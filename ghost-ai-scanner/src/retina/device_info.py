# =============================================================
# FILE: src/retina/device_info.py
# VERSION: 1.0.0
# UPDATED: 2026-09-29
# OWNER: Giggso Inc
# PURPOSE: Cross-platform device metadata collection (no root required).
#          Collected once per process lifetime and cached.
#
# PLATFORMS: Linux, macOS, Windows
# DEPENDS: stdlib only (os, platform, socket, subprocess, sys, uuid)
# =============================================================

from __future__ import annotations

import logging
import os
import platform
import socket
import subprocess
import sys
import uuid

_log = logging.getLogger("marauder-scan.retina.device_info")

_MACHINE_ID_FILE = os.path.expanduser("~/.raven/machine-id")
_cached: dict | None = None


def _get_hardware_uid() -> str:
    """Return a stable, per-machine identifier without requiring root.

    Priority (first non-empty value wins):
      Linux  : /etc/machine-id or /var/lib/dbus/machine-id  (systemd, no sudo)
      macOS  : IOPlatformUUID via ioreg (no sudo)
      Windows: wmic csproduct uuid (no elevation needed for read)
      All    : persisted UUID in ~/.raven/machine-id (generated once, stable)
    """
    # Linux — systemd machine-id (stable across reboots, no sudo)
    if sys.platform.startswith("linux"):
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                uid = open(path).read().strip()
                if uid:
                    return uid
            except OSError:
                pass

    # macOS — IOPlatformUUID via ioreg
    if sys.platform == "darwin":
        try:
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode(errors="replace")
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    uid = line.split("=")[-1].strip().strip('"').strip()
                    if uid:
                        return uid
        except Exception as exc:
            _log.debug("ioreg uid lookup failed: %s", exc)

    # Windows — wmic (available on all Windows versions without elevation)
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["wmic", "csproduct", "get", "uuid", "/value"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode(errors="replace")
            for line in out.splitlines():
                if "UUID=" in line.upper():
                    uid = line.split("=", 1)[-1].strip()
                    # Ignore the all-F placeholder some VMs emit
                    if uid and uid.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                        return uid
        except Exception as exc:
            _log.debug("wmic uid lookup failed: %s", exc)

    # Persisted fallback — generate once, write to ~/.raven/machine-id
    try:
        if os.path.isfile(_MACHINE_ID_FILE):
            uid = open(_MACHINE_ID_FILE).read().strip()
            if uid:
                return uid
    except OSError:
        pass

    uid = str(uuid.uuid4())
    try:
        os.makedirs(os.path.dirname(_MACHINE_ID_FILE), exist_ok=True)
        with open(_MACHINE_ID_FILE, "w") as f:
            f.write(uid)
    except OSError as exc:
        _log.debug("could not persist machine-id: %s", exc)
    return uid


def _get_device_name() -> str:
    """Return a human-readable device / computer name.

    macOS  : ComputerName from scutil (friendly name, e.g. "M Ahsan's MacBook Pro")
    Windows: %COMPUTERNAME% env var
    Linux  : hostname (socket.gethostname())
    """
    if sys.platform == "darwin":
        try:
            name = subprocess.check_output(
                ["scutil", "--get", "ComputerName"],
                stderr=subprocess.DEVNULL, timeout=3,
            ).decode().strip()
            if name:
                return name
        except Exception:
            pass

    if sys.platform == "win32":
        name = os.environ.get("COMPUTERNAME", "").strip()
        if name:
            return name

    return socket.gethostname()


def _get_os_version() -> str:
    """Return a concise OS version string.

    macOS  : "macOS 15.2"   (via sw_vers)
    Windows: "Windows 11"   (via platform)
    Linux  : "Linux 6.17.0" (platform.system + platform.release)
    """
    system = platform.system()

    if system == "Darwin":
        try:
            ver = subprocess.check_output(
                ["sw_vers", "-productVersion"],
                stderr=subprocess.DEVNULL, timeout=3,
            ).decode().strip()
            if ver:
                return f"macOS {ver}"
        except Exception:
            pass
        return f"macOS {platform.mac_ver()[0]}".strip()

    if system == "Windows":
        rel = platform.release()   # "10", "11"
        return f"Windows {rel}".strip()

    # Linux and everything else
    return f"{system} {platform.release()}".strip()


def get_device_info() -> dict:
    """Return cached device metadata dict.

    Keys: device_name (str), hardware_uid (str), os_version (str).
    Collected once per process; subsequent calls return the cached result.
    Never raises — returns empty strings on any collection failure.
    """
    global _cached
    if _cached is not None:
        return _cached

    try:
        info = {
            "device_name":  _get_device_name(),
            "hardware_uid": _get_hardware_uid(),
            "os_version":   _get_os_version(),
        }
    except Exception as exc:
        _log.warning("device_info collection failed: %s", exc)
        info = {"device_name": "", "hardware_uid": "", "os_version": ""}

    _cached = info
    _log.info(
        "device_info collected: name=%r uid=%.8s… os=%r",
        info["device_name"], info["hardware_uid"] or "?", info["os_version"],
    )
    return _cached
