#!/bin/bash
# =============================================================
# FILE: agent/capture/install/install-mac.sh
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Install the PatronAI capture companion on macOS.
#          Two LaunchDAEMONS (not LaunchAgents): capture needs root for BPF.
# =============================================================
# Rendered from a template; double-brace values substituted at invite time.
# Delivered inside a .dmg as a .command - double-clicking opens Terminal, and
# this script asks for sudo at runtime (installer_bundler.py:297).
#
# NOTE the existing scan agent installs LaunchAGENTS under
# ~/Library/LaunchAgents (per-user, unprivileged). Capture cannot use those:
# reading from BPF devices requires root. Hence LaunchDaemons.
# =============================================================
set -euo pipefail

TOKEN="{{TOKEN}}"
DEVICE_ID="{{DEVICE_ID}}"
COMPANY="{{COMPANY}}"
URLS_JSON='{{URLS_JSON}}'
WIRESHARK_URL="{{WIRESHARK_URL}}"
WIRESHARK_SHA256="{{WIRESHARK_SHA256}}"

WIRESHARK_VERSION="4.6.8"
DATA_DIR="/Library/Application Support/PatronAI/capture"
CODE_DIR="$DATA_DIR/code"
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_info() { echo "[capture] $*"; }
_ok()   { echo "[capture] + $*"; }
_die()  { echo "[capture] X $*" >&2; exit 1; }

echo; echo "PatronAI Capture Companion - macOS"; echo "=================================="; echo

# ── 1. Elevation ─────────────────────────────────────────────────────────
# Hard-fail rather than install something that silently collects nothing.
if [ "$(id -u)" -ne 0 ]; then
  _info "Administrator rights are required (packet capture needs root)."
  exec sudo -p "[capture] Password for %u: " bash "$0" "$@"
fi
_ok "Running as root"

# ── 2. Prerequisites ─────────────────────────────────────────────────────
# macOS has not shipped Python 3 in the base system for years - `python3` is
# a stub that triggers an Xcode Command Line Tools install. Check for a REAL
# interpreter, not just the presence of the name on PATH.
command -v python3 >/dev/null 2>&1 || _die "Python 3 is required."
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null \
  || _die "Python 3.8+ is required. If macOS prompted for Command Line Tools, install them and re-run."
_ok "Python $(python3 -c 'import sys;print(".".join(map(str,sys.version_info[:3])))')"

# tcpdump is built into macOS, but we use dumpcap (ships with Wireshark)
# because it writes pcapng directly and rotates on a duration.

# ── 3. Wireshark, pinned ─────────────────────────────────────────────────
if [ -x "$TSHARK" ]; then
  INSTALLED="$("$TSHARK" -v 2>/dev/null | head -1)"
  case "$INSTALLED" in
    *"$WIRESHARK_VERSION"*) _ok "tshark $WIRESHARK_VERSION already installed" ;;
    # Never silently overwrite: that downgrades tooling the user may rely on.
    *) _die "A different Wireshark is installed ($INSTALLED). Expected $WIRESHARK_VERSION." ;;
  esac
else
  _info "Downloading Wireshark $WIRESHARK_VERSION..."
  DMG="$(mktemp -t wireshark).dmg"
  curl -fsSL "$WIRESHARK_URL" -o "$DMG"
  ACTUAL="$(shasum -a 256 "$DMG" | awk '{print $1}')"
  [ "$ACTUAL" = "$WIRESHARK_SHA256" ] || { rm -f "$DMG"; _die "Checksum mismatch: expected $WIRESHARK_SHA256, got $ACTUAL"; }
  _ok "Checksum verified"

  MOUNT="$(hdiutil attach -nobrowse -quiet "$DMG" | awk 'END{print $NF}')"
  installer -pkg "$MOUNT"/Wireshark*.pkg -target / >/dev/null
  hdiutil detach -quiet "$MOUNT" || true
  rm -f "$DMG"
  [ -x "$TSHARK" ] || _die "Wireshark install did not produce $TSHARK"
  _ok "Wireshark $WIRESHARK_VERSION installed"
fi

# ── 4. Directories, locked down ──────────────────────────────────────────
# The keylog here is a master key to every TLS session on this machine.
mkdir -p "$CODE_DIR" "$DATA_DIR"/{keylog,capture,spool,state,logs}
chown -R root:wheel "$DATA_DIR"
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
# launchctl setenv applies to processes launched by launchd from now on. It
# does NOT persist across reboot on its own, so a LaunchDaemon re-applies it
# at boot - without that, coverage silently stops after the first restart.
KEYLOG="$DATA_DIR/keylog/sslkeys.log"
launchctl setenv SSLKEYLOGFILE "$KEYLOG"

cat > /Library/LaunchDaemons/com.patronai.capture.setenv.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.patronai.capture.setenv</string>
  <key>ProgramArguments</key>
  <array><string>launchctl</string><string>setenv</string>
         <string>SSLKEYLOGFILE</string><string>$KEYLOG</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
_ok "SSLKEYLOGFILE set machine-wide (and re-applied at boot)"

# ── 7. Daemons ───────────────────────────────────────────────────────────
# capture: RunAtLoad + KeepAlive, runs forever.
# sync:    StartInterval 3600, short-lived.
cat > /Library/LaunchDaemons/com.patronai.capture.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.patronai.capture</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/python3</string><string>$CODE_DIR/capture_service.py</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DATA_DIR/logs/capture.log</string>
  <key>StandardErrorPath</key><string>$DATA_DIR/logs/capture.err</string>
</dict></plist>
PLIST

cat > /Library/LaunchDaemons/com.patronai.capture.sync.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.patronai.capture.sync</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/python3</string><string>$CODE_DIR/sync_task.py</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>StandardOutPath</key><string>$DATA_DIR/logs/sync.log</string>
  <key>StandardErrorPath</key><string>$DATA_DIR/logs/sync.err</string>
</dict></plist>
PLIST

chmod 644 /Library/LaunchDaemons/com.patronai.capture*.plist
chown root:wheel /Library/LaunchDaemons/com.patronai.capture*.plist
for L in com.patronai.capture.setenv com.patronai.capture com.patronai.capture.sync; do
  launchctl bootout system "/Library/LaunchDaemons/$L.plist" 2>/dev/null || true
  launchctl bootstrap system "/Library/LaunchDaemons/$L.plist"
done
_ok "Registered capture (boot) and sync (hourly) daemons"

# ── 8. Browser restart prompt ────────────────────────────────────────────
echo
echo "  Browsers and desktop apps already running were started before TLS"
echo "  key logging was enabled, so their traffic cannot be decoded until"
echo "  they restart. Closing and reopening them now gives full coverage"
echo "  immediately; otherwise it arrives as they restart naturally."
echo
_ok "Install complete"
