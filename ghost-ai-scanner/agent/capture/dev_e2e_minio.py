#!/usr/bin/env python3
# =============================================================
# FILE: agent/capture/dev_e2e_minio.py
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: DEV ONLY. End-to-end check of the capture companion against a
#          local MinIO, driving the REAL server-side minting in
#          store/agent_store.py - not a mock of it.
# =============================================================
"""Dev end-to-end: real agent_store minting -> MinIO -> real companion code.

This is deliberately NOT a mock. It calls the same AgentStore methods the
/agent/provision endpoint calls, so a break in the minting path fails here
rather than on a device.

What it proves, in order:
  1. get_presigned_urls() emits capture_post + code_manifest_url
  2. write_code_manifest() publishes real file hashes
  3. write_url_bundle() carries both through to urls.json
  4. The companion's integrity check passes against the published manifest
  5. sync_task uploads a real spool file and verifies its ETag
  6. The object lands at the expected key
  7. TAMPERING a code file makes the companion REFUSE TO RUN

Prerequisites: MinIO on :9000 (container `local-storage`).

  python dev_e2e_minio.py
  python dev_e2e_minio.py --keep     # leave the temp DATA_DIR in place
"""
import argparse
import gzip
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCANNER_ROOT = HERE.parent.parent          # ghost-ai-scanner/
sys.path.insert(0, str(SCANNER_ROOT / "src"))
sys.path.insert(0, str(HERE))

BUCKET = os.environ.get("DEV_BUCKET", "patronai-dev")
TOKEN = os.environ.get("DEV_TOKEN", "a3f9c1e2")

# MinIO, as it runs in the `local-storage` container today.
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


def step(n, msg):
    print(f"\n[{n}] {msg}")


def ok(msg):
    print(f"    OK  {msg}")


def main(keep: bool = False, pcap: Path = None, keylog: Path = None) -> int:
    from store.agent_store import AgentStore, CAPTURE_PREFIX

    data_dir = Path(tempfile.mkdtemp(prefix="patronai-e2e-"))
    os.environ["PATRONAI_CAPTURE_DIR"] = str(data_dir)
    # Import AFTER PATRONAI_CAPTURE_DIR is set - paths() reads it at call time,
    # but being explicit here keeps the ordering obvious to a reader.
    import common
    import sync_task

    store = AgentStore(BUCKET)
    try:
        store.s3.create_bucket(Bucket=BUCKET)
    except Exception:
        pass

    try:
        # ── 1. Real minting ──────────────────────────────────────────
        step(1, "AgentStore.get_presigned_urls() - the real server-side mint")
        urls = store.get_presigned_urls(TOKEN, "windows")
        assert urls, "get_presigned_urls returned nothing"
        assert "capture_post" in urls, "capture_post missing from the bundle"
        assert "code_manifest_url" in urls, "code_manifest_url missing from the bundle"
        post = urls["capture_post"]
        assert post.get("url") and post.get("fields"), post
        ok(f"capture_post minted, fields: {sorted(post['fields'])}")
        ok(f"policy prefix: {CAPTURE_PREFIX}/{TOKEN}/")

        # ── 2. Publish the code manifest ─────────────────────────────
        step(2, "write_code_manifest() - hashes of the real companion files")
        manifest = common.local_manifest(HERE)
        assert manifest, "no companion files found to hash"
        assert store.write_code_manifest(TOKEN, manifest), "manifest publish failed"
        for name, digest in sorted(manifest.items()):
            ok(f"{name}: {digest[:16]}...")

        # ── 3. Bundle carries both through ───────────────────────────
        step(3, "write_url_bundle() - what the device actually reads")
        assert store.write_url_bundle(TOKEN, "windows"), "write_url_bundle failed"
        bundle = json.loads(store._get(f"config/HOOK_AGENTS/{TOKEN}/urls.json"))
        assert bundle.get("capture_post", {}).get("url"), "capture_post lost in the bundle"
        assert bundle.get("code_manifest_url"), "code_manifest_url lost in the bundle"
        ok(f"urls.json keys: {sorted(bundle)}")

        # ── 4. Stand in for the installer ────────────────────────────
        step(4, "Writing config.json + urls.json (what the installer does)")
        paths = common.ensure_dirs()
        common.write_atomic(paths["state"] / "config.json", json.dumps(
            {"token": TOKEN, "device_id": "dev-device", "company": "giggso"}).encode())
        common.write_atomic(paths["state"] / "urls.json", json.dumps(bundle).encode())
        ok(f"DATA_DIR = {data_dir}")

        # ── 5. Integrity, against the published manifest ─────────────
        step(5, "Companion integrity check")
        status, detail = common.verify_integrity(HERE)
        assert status == common.OK, f"expected OK, got {status}: {detail}"
        ok(f"{status} - {detail}")

        # ── 5b. Real capture pipeline, when a pcapng is supplied ─────
        # This is the difference between testing the transport and testing
        # the PRODUCT: it runs capture_service.process_segment(), which
        # shells out to the real parser and seals a real spool file.
        if pcap:
            step("5b", f"process_segment() on a REAL capture - {pcap.name}")
            import capture_service
            if not keylog or not keylog.exists():
                raise SystemExit("--pcap needs --keylog (TLS session keys)")
            shutil.copy2(keylog, paths["keylog"] / "sslkeys.log")
            staged = paths["capture"] / f"seg_{'7b2e9f04'}_001.pcapng"
            shutil.copy2(pcap, staged)
            ok(f"staged {staged.name} ({staged.stat().st_size / 1e6:.1f} MB) "
               f"+ keylog ({keylog.stat().st_size / 1e6:.1f} MB)")
            print("      running tshark (4 passes over the capture) - this takes a while...")

            sealed = capture_service.process_segment(staged, paths, "7b2e9f04")
            assert sealed and sealed.exists(), "process_segment produced no spool file"
            raw = gzip.decompress(sealed.read_bytes())
            rows = [json.loads(x) for x in raw.splitlines() if x.strip()]
            assert rows, "no records extracted from the capture"
            ok(f"{sealed.name}: {len(rows)} records, "
               f"{sealed.stat().st_size / 1024:.0f} KB gzipped "
               f"({len(raw) / 1024:.0f} KB raw)")

            # The policy must hold on real traffic, not just fixtures.
            leaked_bodies = [r for r in rows if r.get("request_body") is not None
                             or r.get("response_body") is not None]
            leaked_cookies = [r for r in rows
                              for k, v in (r.get("request_headers") or {}).items()
                              if k.lower() == "cookie" and v != "[REDACTED]"]
            assert not leaked_bodies, f"{len(leaked_bodies)} records LEAKED BODIES"
            assert not leaked_cookies, f"{len(leaked_cookies)} records LEAKED COOKIES"
            versions = {r.get("parser_version") for r in rows}
            assert versions == {"2026-09-01.1"}, f"unexpected parser_version: {versions}"
            domains = sorted({r.get("destination_domain") for r in rows
                              if r.get("destination_domain")})
            ok(f"0 bodies, 0 raw cookies, parser_version={versions.pop()}")
            ok(f"{len(domains)} distinct domains, e.g. {domains[:4]}")
            assert not (paths["capture"] / staged.name).exists(), \
                "raw capture should be deleted once records are safely spooled"
            ok("raw .pcapng deleted after successful extraction")

        # ── 6. Real upload through sync_task ─────────────────────────
        step(6, "sync_task.run_once() - real upload + ETag verification")
        if not pcap:
            spool_file = paths["spool"] / "20260901T141503Z-7b2e9f04-0001.jsonl.gz"
            records = b"".join(
                json.dumps({"timestamp": "1788000000.0",
                            "destination_domain": d,
                            "parser_version": "2026-09-01.1",
                            "request_body": None, "response_body": None}).encode() + b"\n"
                for d in ("chatgpt.com", "claude.ai", "gemini.google.com"))
            common.write_atomic(spool_file, gzip.compress(records))
            ok(f"staged {spool_file.name} ({spool_file.stat().st_size} bytes)")
        spooled = sorted(paths["spool"].glob("*.jsonl.gz"))
        assert spooled, "nothing in the spool to upload"

        result = sync_task.run_once()
        assert result["uploaded"] == len(spooled), f"expected {len(spooled)} upload(s), got {result}"
        assert not any(f.exists() for f in spooled), \
            "spool files must be deleted after a confirmed upload"
        ok(f"uploaded={result['uploaded']} failed={result['failed']} dropped={result['dropped']}")
        ok("spool file deleted only after ETag verification")

        # ── 7. Confirm the key layout in MinIO ───────────────────────
        step(7, "Object landed in MinIO at the expected key")
        listing = store.s3.list_objects_v2(
            Bucket=BUCKET, Prefix=f"{CAPTURE_PREFIX}/{TOKEN}/").get("Contents", [])
        assert listing, "nothing under the capture prefix"
        keys = [o["Key"] for o in listing]
        # The key must be exactly what sync_task derives from the filename -
        # re-derived here rather than hardcoded, so this also proves the key
        # is reconstructible from the file alone (what makes re-upload safe).
        for f in spooled:
            expected = sync_task.s3_key_for(f.name, TOKEN)
            assert expected in keys, f"expected {expected}, found {keys}"
        for o in listing:
            ok(f"{o['Key']}  ({o['Size']} bytes)")

        # Round-trip the content to prove it is readable and policy-clean.
        expected = sync_task.s3_key_for(spooled[0].name, TOKEN)
        body = store.s3.get_object(Bucket=BUCKET, Key=expected)["Body"].read()
        rows = [json.loads(x) for x in gzip.decompress(body).splitlines() if x.strip()]
        assert rows, "downloaded object had no records"
        assert all(r.get("request_body") is None for r in rows), "BODY LEAKED TO THE LAKE"
        ok(f"round-tripped {len(rows)} records from the lake, no bodies present")

        # ── 8. Tamper detection ──────────────────────────────────────
        step(8, "Tampering with companion code must REFUSE TO RUN")
        target = HERE / "common.py"
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"\n# injected\n")
            status, detail = common.verify_integrity(HERE)
            assert status == common.MISMATCH, f"tampering NOT detected: {status}"
            ok(f"{status} - {detail}")
            try:
                common.require_integrity(logger=lambda m: None)
                raise AssertionError("require_integrity should have exited")
            except SystemExit as exc:
                ok(f"refused to run: {str(exc)[:90]}...")
        finally:
            target.write_bytes(original)
        status, _ = common.verify_integrity(HERE)
        assert status == common.OK, "restore failed - file left modified!"
        ok("original restored, integrity back to OK")

        print("\n" + "=" * 62)
        print("  A+3 END-TO-END PASS - real minting -> MinIO -> real companion")
        print("=" * 62)
        return 0
    finally:
        if keep:
            print(f"\nDATA_DIR kept at {data_dir}")
        else:
            shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true", help="keep the temp DATA_DIR")
    ap.add_argument("--pcap", type=Path,
                    help="run the REAL capture pipeline on this .pcapng "
                         "(tshark -> sanitize -> spool) instead of fabricating records")
    ap.add_argument("--keylog", type=Path, help="TLS keylog for --pcap")
    a = ap.parse_args()
    sys.exit(main(a.keep, a.pcap, a.keylog))
