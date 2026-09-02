#!/usr/bin/env python3
# =============================================================
# FILE: scripts/verify_storage.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc
# PURPOSE: Prove the configured object store actually works before the app
#          depends on it. Exercises every verb the codebase uses, against
#          whatever STORAGE_MODE points at - S3, MinIO, LocalStack, Azure
#          or GCS.
# =============================================================
"""Verify the configured object store end to end.

Run this after pointing the stack at a new backend. It uses the same
`get_object_store()` / `boto3_s3_client()` the application uses, so a pass
here means the app's storage calls will work - and a failure names the verb
that broke instead of surfacing later as a confusing feature bug.

Two capabilities are checked but NOT required, because the code already
degrades cleanly when they are missing:

  * S3 Select      - MinIO DOES implement it (verified), LocalStack does not.
                     Either way findings_store and hourly_rollup fall back to
                     GetObject, gated on base_store.is_s3_compatible_local(),
                     which skips Select for ANY local endpoint. Slower, correct.
  * Lifecycle      - chat/history.ensure_lifecycle_policy() catches its own
                     failure and logs a warning; chat still works, objects
                     just are not auto-expired.

  python scripts/verify_storage.py
  python scripts/verify_storage.py --bucket my-bucket
"""
import argparse
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

PASS, FAIL, SKIP = "PASS", "FAIL", "n/a "
_results = []


def check(name: str, fn, required: bool = True):
    """Run one probe. Never raises - a failure is data, not a crash."""
    try:
        detail = fn()
        _results.append((PASS, name, detail or ""))
    except Exception as exc:
        _results.append((FAIL if required else SKIP, name,
                         f"{type(exc).__name__}: {str(exc)[:90]}"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bucket", default=os.environ.get("PATRONAI_BUCKET")
                    or os.environ.get("MARAUDER_SCAN_BUCKET") or "")
    args = ap.parse_args()

    from store.object_store import get_object_store, boto3_s3_client, storage_mode, default_bucket
    from store.base_store import is_s3_compatible_local

    bucket = args.bucket or default_bucket()
    if not bucket:
        print("No bucket configured. Set PATRONAI_BUCKET or pass --bucket.", file=sys.stderr)
        return 2

    mode = storage_mode()
    endpoint = (os.environ.get("LOCAL_STORAGE_ENDPOINT")
                or os.environ.get("AWS_ENDPOINT_URL") or "(AWS default)")
    print(f"storage mode : {mode}")
    print(f"endpoint     : {endpoint}")
    print(f"bucket       : {bucket}")
    print(f"S3 Select    : {'skipped by design' if is_s3_compatible_local() else 'will be attempted'}")
    print()

    store = get_object_store()
    key = f"_verify/{uuid.uuid4().hex}.json"
    body = b'{"verify":true}'

    check("put", lambda: (store.put(bucket, key, body, "application/json"), "wrote probe object")[1])
    check("get", lambda: "round-tripped" if store.get(bucket, key) == body
          else (_ for _ in ()).throw(AssertionError("content mismatch")))
    check("exists", lambda: "found" if store.exists(bucket, key)
          else (_ for _ in ()).throw(AssertionError("object not found")))
    check("list_keys", lambda: f"{len(store.list_keys(bucket, '_verify/'))} key(s) under prefix")

    client = boto3_s3_client()
    check("paginator", lambda: f"{sum(len(p.get('Contents', [])) for p in client.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix='_verify/'))} object(s) paged")

    # Presigned POST is what the capture companion uploads with. It is the
    # one verb with no fallback anywhere - if it fails, devices cannot ship.
    check("presigned_post", lambda: "policy minted" if client.generate_presigned_post(
        Bucket=bucket, Key="_verify/${filename}",
        Conditions=[["starts-with", "$key", "_verify/"]], ExpiresIn=60).get("url")
        else (_ for _ in ()).throw(AssertionError("no url returned")))

    def _select():
        """Must CONSUME the payload stream, not just issue the call.

        select_object_content returns lazily - the request is only sent when
        the EventStream is iterated. Checking the return value alone makes
        this probe incapable of failing, which is worse than no probe: it
        would report 'supported' against any backend, working or not.
        """
        resp = client.select_object_content(
            Bucket=bucket, Key=key, ExpressionType="SQL",
            Expression="SELECT * FROM s3object s LIMIT 1",
            InputSerialization={"JSON": {"Type": "LINES"}},
            OutputSerialization={"JSON": {}})
        for _ in resp["Payload"]:
            break
        return "supported - push-down filtering active"

    def _lifecycle():
        client.get_bucket_lifecycle_configuration(Bucket=bucket)
        return "readable"

    check("s3_select", _select, required=False)
    check("lifecycle", _lifecycle, required=False)

    check("delete", lambda: "removed" if (store.delete(bucket, key), not store.exists(bucket, key))[1]
          else (_ for _ in ()).throw(AssertionError("object survived delete")))

    width = max(len(n) for _, n, _ in _results)
    for status, name, detail in _results:
        print(f"  [{status}] {name.ljust(width)}  {detail}")

    failed = [n for s, n, _ in _results if s == FAIL]
    print()
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        print("The app will not work correctly against this backend.")
        return 1
    optional = [n for s, n, _ in _results if s == SKIP]
    if optional:
        print(f"Unsupported but non-fatal: {', '.join(optional)} - the code falls back.")
    print("Storage backend OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
