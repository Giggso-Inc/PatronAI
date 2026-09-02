#!/usr/bin/env python3
# =============================================================
# FILE: agent/capture/dev_render_installer.py
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: DEV ONLY. Render a runnable capture installer by substituting
#          real minted values into the {{PLACEHOLDER}} template - the same
#          substitution render_agent_package.py does for the scan agent.
# =============================================================
"""Render a real, runnable capture installer against local MinIO.

Stands in for render_agent_package.py, which does not know about capture yet.
Everything it substitutes comes from the REAL AgentStore minting path, so the
rendered installer is what a genuine invite would produce - only the delivery
(email, NSIS .exe wrapper) is skipped.

  python dev_render_installer.py                 # writes dev_out/
  python dev_render_installer.py --token mydev   # pick the device token

The rendered script is NOT executed. Read it, then run it yourself elevated.
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCANNER_ROOT = HERE.parent.parent
sys.path.insert(0, str(SCANNER_ROOT / "src"))
sys.path.insert(0, str(HERE))

# Local MinIO dev credentials for the `local-storage` container. These are
# throwaway container defaults, NOT production secrets - but do not add real
# ones here, and note dev_out/ is gitignored because rendered installers embed
# live presigned URLs.
os.environ.setdefault("STORAGE_MODE", "minio")
os.environ.setdefault("LOCAL_STORAGE_ENDPOINT", "http://127.0.0.1:9000")
os.environ.setdefault("LOCAL_STORAGE_ACCESS_KEY", "minioadmin")
# NO hardcoded default: this is a real credential on some machine, and a
# committed default is a committed secret however throwaway it looks.
# Source .env before running - the harness fails loudly if it is unset.
if not os.environ.get("LOCAL_STORAGE_SECRET_KEY"):
    raise SystemExit("LOCAL_STORAGE_SECRET_KEY unset - source .env first")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

# Pinned Wireshark 4.6.8, Windows x64. The .exe (NSIS) NOT the .msi:
#   * msiexec does not accept /S, which the installer passes
#   * /S is also what makes Wireshark skip Npcap - the User's Guide states
#     "the silent installer will not install Npcap", and there is no flag
# SHA256 published by wireshark.org for Wireshark-4.6.8-x64.exe.
WIRESHARK_URL = os.environ.get(
    "WIRESHARK_URL",
    "https://2.na.dl.wireshark.org/win64/Wireshark-4.6.8-x64.exe")
WIRESHARK_SHA256 = os.environ.get(
    "WIRESHARK_SHA256",
    "8eba737cb6875d9b3709228d37893f71125bdc50d7148e24d9cdc755259e9c3a")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--token", default="devlaptop01")
    ap.add_argument("--bucket", default=os.environ.get("DEV_BUCKET", "patronai-dev"))
    ap.add_argument("--company", default="giggso")
    ap.add_argument("--os", dest="os_type", default="windows",
                    choices=["windows", "mac", "linux"])
    ap.add_argument("--out", type=Path, default=HERE / "dev_out")
    args = ap.parse_args()

    import common
    from store.agent_store import AgentStore

    store = AgentStore(args.bucket)
    try:
        store.s3.create_bucket(Bucket=args.bucket)
    except Exception:
        pass

    # 1. Publish the code manifest FIRST. The installer copies these exact
    #    files, and the companion verifies them at every startup - so the
    #    manifest must describe what is about to be installed, not a
    #    previous version.
    manifest = common.local_manifest(HERE)
    if not store.write_code_manifest(args.token, manifest):
        print("ERROR: could not publish the code manifest", file=sys.stderr)
        return 1

    # 2. Mint + persist the URL bundle, exactly as provisioning would.
    if not store.write_url_bundle(args.token, args.os_type):
        print("ERROR: could not write the url bundle", file=sys.stderr)
        return 1
    bundle = json.loads(store._get(f"config/HOOK_AGENTS/{args.token}/urls.json"))
    if not bundle.get("capture_post", {}).get("url"):
        print("ERROR: capture_post missing from the bundle", file=sys.stderr)
        return 1

    # 3. Substitute. The Wireshark values below are the real pinned 4.6.8
    #    Windows x64 NSIS installer and its published SHA256. The .exe is
    #    required, not the .msi: msiexec does not accept the /S switch the
    #    installer passes, and /S is also what makes Wireshark skip Npcap.
    template = (HERE / "install" / f"install-{ {'windows': 'windows',
                                                'mac': 'mac',
                                                'linux': 'linux'}[args.os_type] }"
                f".{'ps1' if args.os_type == 'windows' else 'sh'}")
    text = template.read_text(encoding="utf-8")
    for key, value in {
        "TOKEN": args.token,
        "DEVICE_ID": f"{args.token}-dev",
        "COMPANY": args.company,
        "URLS_JSON": json.dumps(bundle),
        "WIRESHARK_URL": WIRESHARK_URL,
        "WIRESHARK_SHA256": WIRESHARK_SHA256,
    }.items():
        text = text.replace("{{" + key + "}}", value)

    remaining = [ln for ln in text.splitlines() if "{{" in ln and "}}" in ln]
    if remaining:
        print("ERROR: unsubstituted placeholders remain:", file=sys.stderr)
        for ln in remaining:
            print("   ", ln.strip(), file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    rendered = args.out / template.name
    rendered.write_text(text, encoding="utf-8-sig" if args.os_type == "windows" else "utf-8")

    # Ship the uninstaller alongside it - never hand someone an installer
    # without the way back.
    uninstall_src = HERE / "install" / (
        "uninstall-windows.ps1" if args.os_type == "windows" else "uninstall.sh")
    if uninstall_src.exists():
        (args.out / uninstall_src.name).write_text(
            uninstall_src.read_text(encoding="utf-8"),
            encoding="utf-8-sig" if args.os_type == "windows" else "utf-8")

    print(f"Rendered   : {rendered}")
    print(f"Token      : {args.token}")
    print(f"Bucket     : {args.bucket}")
    print(f"Upload URL : {bundle['capture_post']['url']}")
    print(f"Manifest   : {len(manifest)} files hashed")
    print(f"Wireshark  : {WIRESHARK_URL}")
    print(f"             sha256 {WIRESHARK_SHA256[:16]}... (verified by download)")
    print("             downloaded only if 4.6.8 is not already installed")
    print()
    print("Read the script before running it. To install (elevated PowerShell):")
    print(f'  powershell -ExecutionPolicy Bypass -File "{rendered}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
