# =============================================================
# FILE: agent/shared/uploader.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc
# PURPOSE: THE single device-side upload implementation. Every agent that
#          ships data off an endpoint goes through here, so adding a storage
#          backend is one change in one file.
# DEPENDS: stdlib ONLY - no boto3, no requests, no AWS CLI.
# =============================================================
"""One upload path for every agent on the device.

WHY THIS FILE EXISTS
--------------------
Device-side storage code was in three shapes across two agents:

    capture companion   presigned POST via urllib          (backend-agnostic)
    scan agent          curl / Invoke-WebRequest PUT       (backend-agnostic)
    scan agent          `aws s3 cp` for git-diffs          (AWS ONLY)

The third breaks twice over. It hardcodes `s3://`, so it cannot reach MinIO
or any other backend; and it needs long-lived AWS credentials sitting on an
employee laptop, which the presigned paths exist specifically to avoid.

Everything here speaks ONE protocol: an HTTP request to a URL the server
minted. The device never knows which backend is behind it - S3, MinIO,
Azure, GCS. That indifference IS the abstraction. Adding a backend is a
server-side minting change; this file does not change at all.

DELIVERY, AND WHY THERE ARE TWO FORMS
-------------------------------------
The two agents are packaged differently and cannot share an import:

  * capture companion - real .py files on disk, verified against a server
    manifest at startup. Imports this module directly.
  * scan agent - a single rendered scan.sh with Python inlined via heredoc.
    No .py files exist on the device to import.

So `as_inline_source()` returns this module's own upload functions as text,
for the renderer to inline. ONE implementation, two delivery mechanisms -
rather than two implementations that drift apart.

Self-test:  python uploader.py
"""
import hashlib
import json
import mimetypes
import urllib.error
import urllib.request
import uuid
from pathlib import Path

__all__ = ["upload_post", "upload_put", "as_inline_source", "UploadError"]


class UploadError(Exception):
    """Upload did not verifiably succeed. Never delete the source on this."""


# ── the two transports the server can mint ───────────────────────────────
# POST  - one policy authorises MANY keys under a prefix. Used when the
#         device produces a stream of files with rotating names.
# PUT   - one URL is bound to exactly ONE key, so it can only overwrite.
#         Used for snapshots (heartbeat, status, latest scan).

def _multipart(fields: dict, filename: str, content: bytes, content_type: str):
    """Build a multipart/form-data body for an S3-style presigned POST.

    The file part MUST come last: S3 and MinIO both ignore form fields that
    appear after it, so a misplaced file part silently drops the policy and
    signature and the upload fails with an opaque error.
    """
    boundary = f"----PatronAI{uuid.uuid4().hex}"
    head = []
    for name, value in fields.items():
        head.append(f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                    f"{value}\r\n")
    head.append(f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n")
    body = ("".join(head).encode("utf-8") + content
            + f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return body, f"multipart/form-data; boundary={boundary}"


def _verify_etag(headers, content: bytes, where: str) -> None:
    """Compare the returned ETag against the local MD5.

    Deletion of the local copy is the consequence of believing an upload
    worked, so the check is worth its cost. ETag == MD5 only for single-part
    uploads; every agent object here is far below the multipart threshold.
    A backend that returns no ETag is accepted rather than failed - absence
    is not evidence of corruption.
    """
    etag = (headers.get("ETag") or "").strip('"')
    if not etag:
        return
    local = hashlib.md5(content).hexdigest()  # nosec B324 - S3 ETag algorithm, not security
    if etag != local:
        raise UploadError(f"{where}: ETag mismatch (got {etag}, want {local})")


def upload_post(post: dict, key: str, content: bytes,
                content_type: str = None, timeout: int = 120) -> None:
    """Upload to a presigned POST policy. Raises UploadError on any doubt.

    `post` is boto3's {"url": ..., "fields": {...}} verbatim. `key` must sit
    under the prefix the policy authorises, or the backend rejects it.
    """
    if not post or not post.get("url"):
        raise UploadError("no presigned POST policy supplied")
    content_type = content_type or (mimetypes.guess_type(key)[0] or "application/octet-stream")

    fields = dict(post.get("fields", {}))
    fields["key"] = key
    fields.setdefault("Content-Type", content_type)

    body, ctype = _multipart(fields, Path(key).name, content, content_type)
    req = urllib.request.Request(post["url"], data=body, method="POST")
    req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not 200 <= resp.status < 300:
                raise UploadError(f"POST {key}: HTTP {resp.status}")
            _verify_etag(resp.headers, content, f"POST {key}")
    except UploadError:
        raise
    except (urllib.error.URLError, OSError) as exc:
        raise UploadError(f"POST {key}: {exc}") from exc


def upload_put(url: str, content: bytes,
               content_type: str = "application/json", timeout: int = 120) -> None:
    """Upload to a presigned PUT URL (one URL, one fixed key).

    The content type MUST match what the URL was signed with, or the
    signature check fails - which surfaces as a confusing 403.
    """
    if not url:
        raise UploadError("no presigned PUT url supplied")
    req = urllib.request.Request(url, data=content, method="PUT")
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not 200 <= resp.status < 300:
                raise UploadError(f"PUT: HTTP {resp.status}")
            _verify_etag(resp.headers, content, "PUT")
    except UploadError:
        raise
    except (urllib.error.URLError, OSError) as exc:
        raise UploadError(f"PUT: {exc}") from exc


# ── delivery to the fragment-rendered scan agent ─────────────────────────

_INLINE_EXPORTS = ("UploadError", "_multipart", "_verify_etag",
                   "upload_post", "upload_put")


def as_inline_source() -> str:
    """This module's upload functions as text, for heredoc inlining.

    The scan agent has no .py files on the device to import, so the renderer
    inlines this instead of the agent carrying its own copy. Read from this
    file at render time, so the inlined code is always what is on disk here -
    it cannot silently drift from what the companion imports.
    """
    src = Path(__file__).read_text(encoding="utf-8")
    out = ["import hashlib, json, mimetypes, urllib.error, urllib.request, uuid",
           "from pathlib import Path", ""]
    lines = src.splitlines()
    for i, line in enumerate(lines):
        if not (line.startswith("def ") or line.startswith("class ")):
            continue
        name = line.split("(")[0].split()[1].rstrip(":")
        if name not in _INLINE_EXPORTS:
            continue
        block = [line]
        for nxt in lines[i + 1:]:
            if nxt and not nxt[0].isspace():
                break
            block.append(nxt)
        out.append("\n".join(block).rstrip())
        out.append("")
    return "\n".join(out)


def _selftest():
    # Multipart: the file part must be LAST or the policy is silently dropped.
    body, ctype = _multipart({"key": "k", "policy": "p"}, "f.gz", b"DATA", "application/gzip")
    assert ctype.startswith("multipart/form-data; boundary=----PatronAI"), ctype
    assert body.index(b'name="key"') < body.index(b'name="file"'), "file part must be last"
    assert body.index(b'name="policy"') < body.index(b'name="file"'), "file part must be last"
    assert b"DATA" in body and body.rstrip().endswith(b"--")

    # ETag verification: match passes, mismatch raises, absence is tolerated.
    payload = b"hello"
    good = {"ETag": '"' + hashlib.md5(payload).hexdigest() + '"'}  # nosec B324
    _verify_etag(good, payload, "t")
    _verify_etag({}, payload, "t")
    try:
        _verify_etag({"ETag": '"deadbeef"'}, payload, "t")
        raise AssertionError("mismatched ETag must raise")
    except UploadError:
        pass

    # Missing credentials must raise, never silently no-op - a no-op would
    # let the caller delete its local copy of data that never uploaded.
    for fn, args in ((upload_post, ({}, "k", b"x")), (upload_put, ("", b"x"))):
        try:
            fn(*args)
            raise AssertionError(f"{fn.__name__} must raise without a url")
        except UploadError:
            pass

    # The inline form must carry every export and stay valid Python.
    import ast
    src = as_inline_source()
    ast.parse(src)
    for name in _INLINE_EXPORTS:
        assert f"def {name}" in src or f"class {name}" in src, f"{name} missing from inline source"

    print("uploader self-test: PASS")


if __name__ == "__main__":
    _selftest()
