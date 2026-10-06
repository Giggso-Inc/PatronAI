# Patron S3 storage + DB object audit

How Patron stores data in object storage (S3 / Azure / GCS / MinIO), what the
JSON/JSONL looks like, and how to map **one user’s** writes via the policy DB
back to the object in S3.

> Migrations: `0009_object_blobs`, `0010_object_blob_audits`  
> Code: `ghost-ai-scanner/src/db/object_blob_ledger.py`, `models_object_blob.py`  
> Writes are recorded only when the put goes through Patron’s `ObjectStore` /
> wrapped `put_object`. Content of the file is **not** copied into Postgres.

---

## 1. Mental model

| Layer | What it holds |
|-------|----------------|
| **S3 (object store)** | The actual JSON / JSONL / CSV / scripts |
| **`object_blobs`** | Latest metadata for each `bucket` + `object_key` |
| **`object_blob_audits`** | Append-only history: one row per successful put |

```
User / system write
        │
        ▼
  ObjectStore.put / put_object
        │
        ├──────────────► S3 object (full body)
        │
        └──────────────► DB: upsert object_blobs
                         + insert object_blob_audits
```

---

## 2. What we store in S3 (by data type)

Patron does **not** use “one JSON file per user for everything.” Layout is by
**data type**. Users appear differently depending on the type.

### 2.1 Users / roles — one shared JSON

| | |
|--|--|
| **Key** | `users/users.json` |
| **Shape** | Single JSON object: `{ "<email>": { "role", "is_admin", "added_at", "added_by" }, ... }` |
| **Per-user?** | All users in **one** file |

Example:

```json
{
  "alice@example.com": {
    "role": "manager",
    "is_admin": false,
    "added_at": "2026-10-01T12:00:00+00:00",
    "added_by": "admin@example.com"
  }
}
```

### 2.2 Chat history — per-user folder (email hashed)

| | |
|--|--|
| **Key** | `chat/{sha256(email)[:16]}/{view}/YYYY-MM-DD.jsonl` |
| **Shape** | JSONL: one chat message object per line |
| **Per-user?** | Yes — folder is privacy-safe hash of email, not plaintext |

Example key: `chat/a1b2c3d4e5f67890/admin/2026-10-06.jsonl`

### 2.3 Findings / scan events — shared by day + severity

| | |
|--|--|
| **Key** | `findings/YYYY/MM/DD/{severity}.jsonl` (also similar under `ocsf/...`) |
| **Shape** | JSONL: one finding/event object per line (many users possible) |
| **Per-user?** | No — shared file; search inside for user fields |

Example key: `findings/2026/10/06/high.jsonl`

### 2.4 Agent / device config — per agent token

| | |
|--|--|
| **Keys** | `config/HOOK_AGENTS/{token}/meta.json`, `status.json`, `authorized.csv`, `urls.json`, … |
| | `ocsf/agent/heartbeats/{token}/latest.json`, `ocsf/agent/scans/{token}/latest.json` |
| **Shape** | JSON (or CSV) scoped to an **agent token**, not a human email |
| **Per-user?** | Indirect — `meta.json` often has `recipient_email` |

### 2.5 Settings / catalogs / rollups — shared / system

Examples: agent catalog, settings blobs, hourly rollup JSON. Usually **not**
one-user files.

---

## 3. What we store in the Patron DB (audit)

We store **metadata only** (path, hash, who, when) — not the full S3 body.

### 3.1 Table `object_blobs` (current state — one row per S3 key)

| Column | Description |
|--------|-------------|
| `id` | UUID PK |
| `bucket` | Bucket / container name |
| `object_key` | Full object path |
| `file_name` | Basename (e.g. `high.jsonl`) |
| `content_hash` | SHA-256 hex of the body at last put |
| `size_bytes` | Body size |
| `content_type` | e.g. `application/json`, `application/x-ndjson` |
| `storage_mode` | `s3` / `azure` / `gcp` / `local` |
| `created_by` | Actor email on **first** write (nullable) |
| `updated_by` | Actor email on **last** write (nullable) |
| `created_by_user_id` | Optional FK → `users.id` |
| `updated_by_user_id` | Optional FK → `users.id` |
| `created_at` | First write time |
| `updated_at` | Last write time |

Unique on `(bucket, object_key)`.

### 3.2 Table `object_blob_audits` (history — one row every put)

| Column | Description |
|--------|-------------|
| `id` | UUID PK |
| `bucket` | Bucket / container |
| `object_key` | Full path |
| `file_name` | Basename |
| `content_hash` | SHA-256 of **that** put’s body |
| `size_bytes` | Size |
| `content_type` | Content type |
| `storage_mode` | Backend mode |
| `action` | Currently `put` |
| `actor_email` | Who wrote it (nullable if unknown) |
| `actor_user_id` | Optional FK → `users.id` |
| `subject_key_hash` | For `chat/{sha16}/…` — the 16-char folder hash |
| `recorded_at` | When this audit row was written |

### 3.3 How `actor_email` is filled

**Verified sources only** (never client-controlled JSON body — spoofing risk):

1. Explicit `actor_email=` / `actor_user_id=` on `record_object_put` / `BaseStore._put`
   (e.g. `UsersStore.upsert(added_by=…)`, `UsersStore.remove(removed_by=…)`,
   `SettingsStore.write(written_by=email)`)
2. Request-scoped context: Raven identity / `resolve_actor` → `set_object_actor`
3. Streamlit dashboard auth gates (`dashboard/ui/auth_gate.py`, `dashboard/auth.py`)
   call `set_object_actor(email=…)` on every authenticated rerun so **all**
   `BaseStore` subclasses (`agent_store`, `settings_store`, `findings_store`, …)
   inherit the logged-in admin without per-store `actor_email=` kwargs
4. `with object_actor(email=…)` (e.g. chat history)

If none apply (scanner/ingestor/system jobs with no human session), `actor_email`
/ `actor_user_id` stay `NULL`. The object is still recorded (hash + key + time).
Payload fields like `recipient_email` are **not** copied into `actor_email`.

### 3.4 Privacy / retention

- Ledger stores **metadata only** (paths, hashes, actor emails) — not S3 body bytes.
- Chat object keys use a privacy-safe email hash prefix (`chat/{sha16}/…`); plaintext
  email is not required in the key.
- `object_blob_audits` is append-only for forensics. **Retention / erasure** for
  actor emails in the policy DB should follow org IAM / GDPR process (manual purge
  or a future scheduled job). This differs from chat S3 objects, which use a
  30-day lifecycle on the bucket objects themselves — the DB audit is the durable
  “who wrote what hash” trail and is not auto-expired with the blob.

### 3.4 What is **not** audited

- Full JSON/JSONL payload (stays only in S3)
- Agent uploads that go **directly** to S3 via **presigned URL** (Patron never sees the put)
- Objects written **before** this ledger was deployed (no backfill)

---

## 4. How to check one user’s logs (DB → S3)

Replace `user@example.com` with the real email.

### Step A — List their audit history

```sql
SELECT
  recorded_at,
  bucket,
  object_key,
  file_name,
  content_hash,
  size_bytes,
  action,
  actor_email,
  subject_key_hash
FROM object_blob_audits
WHERE lower(actor_email) = lower('user@example.com')
ORDER BY recorded_at DESC;
```

Current snapshot of keys they created or last updated:

```sql
SELECT
  bucket,
  object_key,
  file_name,
  content_hash,
  created_by,
  created_at,
  updated_by,
  updated_at
FROM object_blobs
WHERE lower(created_by) = lower('user@example.com')
   OR lower(updated_by) = lower('user@example.com')
ORDER BY updated_at DESC;
```

### Step B — Chat-only lookup via email hash

Patron chat folders use `sha256(lower(email))[:16]`:

```bash
# Python one-liner
python -c "import hashlib; print(hashlib.sha256(b'user@example.com').hexdigest()[:16])"
```

```sql
SELECT recorded_at, bucket, object_key, content_hash, actor_email
FROM object_blob_audits
WHERE subject_key_hash = '<paste-16-hex-here>'
ORDER BY recorded_at DESC;
```

### Step C — Fetch the object from S3

From a row, use `bucket` + `object_key`:

```bash
aws s3 cp "s3://BUCKET/OBJECT_KEY" ./user-check.bin

# Or:
aws s3api get-object --bucket BUCKET --key "OBJECT_KEY" outfile.bin
```

(Azure/GCS: use the same key against the configured container/bucket.)

### Step D — Compare hash (prove DB matches file bytes)

```bash
# Linux / macOS
sha256sum ./user-check.bin

# PowerShell
Get-FileHash .\user-check.bin -Algorithm SHA256
```

The hex digest must equal `content_hash` on the audit / blob row.

### Step E — Interpret the file by type

| If `object_key` looks like… | What to do in the file |
|-----------------------------|-------------------------|
| `chat/{hash}/…/*.jsonl` | Read that user’s chat lines for that day/view |
| `findings/…/*.jsonl` or `ocsf/…` | Search lines for email / user / device — file is **shared**; audit = who **wrote the file**, not every line’s owner |
| `users/users.json` | Look up the email key inside the map — **shared** file |
| `config/HOOK_AGENTS/{token}/…` | Inspect agent meta (`recipient_email`, status, etc.) |

---

## 5. End-to-end example

**User:** `alice@example.com`  
**Chat put today** → S3 key:

`chat/a1b2c3d4e5f67890/admin/2026-10-06.jsonl`

**DB audit row (illustrative):**

| Field | Value |
|-------|--------|
| `object_key` | `chat/a1b2c3d4e5f67890/admin/2026-10-06.jsonl` |
| `file_name` | `2026-10-06.jsonl` |
| `content_hash` | `e3b0c44…` (SHA-256 of body) |
| `actor_email` | `alice@example.com` |
| `subject_key_hash` | `a1b2c3d4e5f67890` |
| `recorded_at` | `2026-10-06T08:00:00Z` |

**Check:**

1. `SELECT … WHERE actor_email = 'alice@example.com'`  
2. `aws s3 cp s3://<bucket>/chat/a1b2…/admin/2026-10-06.jsonl .`  
3. `Get-FileHash` / `sha256sum` → matches `content_hash`  
4. Open JSONL and review messages  

---

## 6. Prerequisites

1. Alembic migrations `0009` and `0010` applied (auto on engine start if Patron auto-migrates).  
2. This ledger code deployed so **new** puts are recorded.  
3. Object store credentials configured (`STORAGE_MODE`, bucket env, etc.).

---

## 7. Related code

| Path | Role |
|------|------|
| `src/db/models_object_blob.py` | SQLAlchemy models |
| `src/db/object_blob_ledger.py` | Hash, upsert, audit insert, actor context |
| `src/store/object_store.py` | Hooks every `put` / wrapped `put_object` |
| `src/chat/history.py` | Sets `object_actor(email=…)` for chat puts |
| `routers/_raven_identity.py` / `_raven_actor.py` | Sets actor from Raven JWT / policy user |
| `alembic/versions/0009_object_blobs.py` | Creates `object_blobs` |
| `alembic/versions/0010_object_blob_audits.py` | Adds `file_name` + `object_blob_audits` |
| `tests/unit/test_object_blob_ledger.py` | Unit tests (mocked DB) |