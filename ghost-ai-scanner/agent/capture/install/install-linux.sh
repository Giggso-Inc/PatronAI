#!/bin/bash
# =============================================================
# FILE: agent/capture/install/install-linux.sh
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Install the PatronAI capture companion on Linux.
#          systemd service (capture, at boot) + timer (sync, hourly).
# =============================================================
# Rendered from a template; double-brace values substituted at invite time.
#
# Linux is the one platform where tshark is NOT exact-pinned: distro repos
# lag well behind current Wireshark releases, so 4.6.8 is generally not
# available as a stock package. We take the distro build, enforce a MINIMUM
# version here, and rely on capture_service.py's startup field check to catch
# any dissector difference that actually matters (PLAN P4b).
# =============================================================
set -euo pipefail

TOKEN="{{TOKEN}}"
DEVICE_ID="{{DEVICE_ID}}"
COMPANY="{{COMPANY}}"
URLS_JSON='{{URLS_JSON}}'

TSHARK_MIN_MAJOR=4
TSHARK_MIN_MINOR=2
DATA_DIR="/var/lib/patronai/capture"
CODE_DIR="$DATA_DIR/code"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_info() { echo "[capture] $*"; }
_ok()   { echo "[capture] + $*"; }
_die()  { echo "[capture] X $*" >&2; exit 1; }

echo; echo "PatronAI Capture Companion - Linux"; echo "=================================="; echo

# ── 0. Clear any previous install FIRST ──────────────────────────────────
# Every fleet upgrade is an install-over-live, and leaving the old service
# running while overwriting its code is how you get an install that reports
# success while the old binary keeps serving. Stop it up front; `|| true` so a
# first-ever install (no units yet) is not an error.
systemctl stop patronai-capture.service 2>/dev/null || true
systemctl stop patronai-capture-sync.timer 2>/dev/null || true
pkill -f capture_service.py 2>/dev/null || true

# ── 1. Elevation ─────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  _info "Root is required (packet capture needs CAP_NET_RAW)."
  exec sudo -p "[capture] Password for %u: " bash "$0" "$@"
fi
_ok "Running as root"

command -v systemctl >/dev/null 2>&1 || _die "systemd is required (systemctl not found)."

# ── 2. Prerequisites ─────────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || _die "Python 3 is required."
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" \
  || _die "Python 3.8+ is required."
_ok "Python $(python3 -c 'import sys;print(".".join(map(str,sys.version_info[:3])))')"

# ── 3. tshark + dumpcap ──────────────────────────────────────────────────
install_tshark() {
  if   command -v apt-get >/dev/null 2>&1; then
    # Suppress the interactive "should non-root capture?" debconf prompt -
    # it hangs a non-interactive install forever.
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q wireshark-cli
  elif command -v yum >/dev/null 2>&1; then yum install -y -q wireshark
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install -y wireshark
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm wireshark-cli
  else _die "No supported package manager found. Install tshark >= ${TSHARK_MIN_MAJOR}.${TSHARK_MIN_MINOR} manually, then re-run."
  fi
}

command -v tshark >/dev/null 2>&1 || { _info "Installing tshark..."; install_tshark; }
command -v tshark >/dev/null 2>&1 || _die "tshark still not on PATH after install."
command -v dumpcap >/dev/null 2>&1 || _die "dumpcap not found - install the Wireshark CLI package."

TSHARK_VER="$(tshark -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
TS_MAJOR="${TSHARK_VER%%.*}"; TS_REST="${TSHARK_VER#*.}"; TS_MINOR="${TS_REST%%.*}"
if [ "$TS_MAJOR" -lt "$TSHARK_MIN_MAJOR" ] || \
   { [ "$TS_MAJOR" -eq "$TSHARK_MIN_MAJOR" ] && [ "$TS_MINOR" -lt "$TSHARK_MIN_MINOR" ]; }; then
  _die "tshark $TSHARK_VER is older than the minimum ${TSHARK_MIN_MAJOR}.${TSHARK_MIN_MINOR}."
fi
_ok "tshark $TSHARK_VER (minimum ${TSHARK_MIN_MAJOR}.${TSHARK_MIN_MINOR}; fields re-checked at every startup)"

# ── 4. Directories, locked down ──────────────────────────────────────────
# The keylog here is a master key to every TLS session on this machine.
mkdir -p "$CODE_DIR" "$DATA_DIR"/{keylog,capture,spool,state,logs}
chown -R root:root "$DATA_DIR"
chmod -R 700 "$DATA_DIR"
_ok "Created $DATA_DIR (root only)"

# ── 5. Companion code + config ───────────────────────────────────────────
# An EXPLICIT list, never a *.py glob: the source tree also contains dev-only
# harnesses carrying local credentials, and a glob would ship them. Must match
# common.py's VERIFIED_FILES or the startup integrity check refuses to run.
for f in pktmon_to_jsonl.py common.py capture_service.py sync_task.py uploader.py; do
  [ -f "$HERE/../$f" ] || _die "Companion file missing from the package: $f"
  cp "$HERE/../$f" "$CODE_DIR"/
done
chmod 600 "$CODE_DIR"/*.py
printf '{"token":"%s","device_id":"%s","company":"%s"}\n' \
  "$TOKEN" "$DEVICE_ID" "$COMPANY" > "$DATA_DIR/state/config.json"
printf '%s\n' "$URLS_JSON" > "$DATA_DIR/state/urls.json"
chmod 600 "$DATA_DIR/state/"*.json
_ok "Installed companion code and config"

# ── 6. SSLKEYLOGFILE, machine-wide ───────────────────────────────────────
# /etc/environment is read by PAM at login, so it reaches desktop sessions -
# which is where the browsers are. It does NOT reach systemd services, but
# those are not what we need to decrypt.
KEYLOG="$DATA_DIR/keylog/sslkeys.log"
sed -i '/^SSLKEYLOGFILE=/d' /etc/environment 2>/dev/null || true
echo "SSLKEYLOGFILE=$KEYLOG" >> /etc/environment
_ok "SSLKEYLOGFILE set in /etc/environment"

# ── 7. systemd units ─────────────────────────────────────────────────────
# capture: a long-running service, restarted on failure.
# sync:    a timer + oneshot, so a hung sync cannot block the next one.
cat > /etc/systemd/system/patronai-capture.service <<UNIT
[Unit]
Description=PatronAI capture companion
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $CODE_DIR/capture_service.py
Restart=on-failure
RestartSec=30
# Root is required for packet capture; AmbientCapabilities alone is not
# enough because dumpcap is executed as a child process.
User=root
StandardOutput=append:$DATA_DIR/logs/capture.log
StandardError=append:$DATA_DIR/logs/capture.err

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/patronai-capture-sync.service <<UNIT
[Unit]
Description=PatronAI capture sync to S3

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $CODE_DIR/sync_task.py
User=root
StandardOutput=append:$DATA_DIR/logs/sync.log
StandardError=append:$DATA_DIR/logs/sync.err
UNIT

cat > /etc/systemd/system/patronai-capture-sync.timer <<UNIT
[Unit]
Description=PatronAI capture sync, hourly

[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
# Without this a laptop that was asleep at the scheduled time simply skips
# the run - and a laptop asleep at the top of every hour would never sync.
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
# `enable --now` does NOT restart a unit that is already running - it starts
# it only if stopped. Installing over a live install would therefore leave the
# OLD process running with the OLD code, and the operator would see a
# successful install with none of the new behaviour. `restart` is what
# guarantees the freshly written code is what actually runs.
systemctl enable patronai-capture.service >/dev/null
systemctl restart patronai-capture.service
systemctl enable --now patronai-capture-sync.timer >/dev/null
_ok "Registered patronai-capture.service (boot) and patronai-capture-sync.timer (hourly)"

# ── 8. Browser restart prompt ────────────────────────────────────────────
echo
echo "  Browsers already running were started before TLS key logging was"
echo "  enabled, so their traffic cannot be decoded until they restart."
echo "  Note /etc/environment is read at LOGIN, so a full log out and back"
echo "  in (or a reboot) is what enrolls a desktop session."
echo
_ok "Install complete"
