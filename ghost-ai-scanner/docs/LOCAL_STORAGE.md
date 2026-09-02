# Running PatronAI against MinIO (or any S3-compatible store)

**Nothing in the application is MinIO-specific.** Every storage call already
routes through `store.object_store.boto3_s3_client()` / `get_object_store()`,
which honour an endpoint override. Pointing the whole stack at MinIO is
configuration, not a code change — and that includes every feature, not just
network capture: findings, agent packages, rollups, chat history, provider
lists, audit logs.

## Start it

```bash
# .env
STORAGE_MODE=minio
LOCAL_STORAGE_ENDPOINT=http://minio:9000     # http://127.0.0.1:9000 from the host
LOCAL_STORAGE_ACCESS_KEY=minioadmin
LOCAL_STORAGE_SECRET_KEY=minioadmin
PATRONAI_BUCKET=patronai-dev
```

```bash
docker compose --profile minio up -d
```

MinIO and its bucket-creation job sit behind a **compose profile**, so without
`--profile minio` the file behaves exactly as it did before. Console:
<http://localhost:9001>.

`minio-init` creates the bucket once MinIO reports healthy. Without it the
first write fails `NoSuchBucket`, which reads like a credentials problem and
sends you looking in the wrong place.

## Verify before trusting it

```bash
python scripts/verify_storage.py --bucket patronai-dev
```

Exercises every verb the codebase uses — put, get, exists, list_keys,
paginator, presigned POST, S3 Select, lifecycle, delete — through the same
client the app uses. A failure names the verb rather than surfacing later as a
confusing feature bug.

Verified against MinIO (2026-09-02): **all required verbs pass.**

## What differs, and why nothing breaks

| Capability | MinIO | Consequence |
|---|---|---|
| get / put / delete / exists / list | ✅ | — |
| Paginator | ✅ | — |
| **Presigned POST** | ✅ | The capture companion's upload path. **No fallback exists** — if this failed, devices could not ship data. |
| S3 Select | ✅ *(LocalStack: ✗)* | Skipped regardless — see below |
| Bucket lifecycle | ✗ | `chat/history.ensure_lifecycle_policy()` catches and warns. Chat works; objects are not auto-expired. |

### S3 Select is skipped on purpose

`base_store.is_s3_compatible_local()` returns `True` for **any** local
endpoint, so `findings_store.read()` and `hourly_rollup` take their
`GetObject` fallback and filter in memory. MinIO does implement Select, but
the gate is deliberately conservative: LocalStack does not, and the fallback
is correct everywhere. Slower on large files, never wrong.

## Which backend an already-installed agent uploads to

⚠️ **Decided when the URL bundle is minted, not at install time.** A capture
companion POSTs to whatever `urls.json` handed it, and that bundle is frozen
for up to 7 days. Switching the server between MinIO and S3 does **not** move
an installed device until its next 24-hour re-mint.

Also: a `127.0.0.1` endpoint only works when the device *is* the MinIO host.
For a second machine, mint with a LAN-reachable address.

## Other backends

`STORAGE_MODE` also accepts `s3`, `azure` and `gcp` — see `object_store.py`.
`verify_storage.py` works against all of them.
