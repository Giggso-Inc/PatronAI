# Raven + Patron Anti-Tamper Plan

**Status:** Plan (not implemented)  
**Date:** 2026-10-06  
**Reference product:** Cowork DLP anti-tamper (`dlp_installer/features/90_antitamper` → `dlp_antitamper_events` → Hub `alert_code=tamper` → admin email)

---

## 1. Goal

When a developer alters, deletes, or disables protected Raven or Patron agent surfaces on a workstation, the system must:

1. **Detect** the change (file/folder hash integrity + optional restore).
2. **Persist** an audit event in DB with a **user FK**.
3. **Alert** Security Admin + Org Admin **and** the developer (actor) via email + in-app.
4. On **official version upgrade**, rebuild baseline and update DB enrollment — **without** false-positive tamper alerts.

This is a **detection and audit** control (same honesty as Cowork): a local admin can kill the watcher or rewrite baseline; we still raise the cost and leave a trail.

---

## 2. Cowork Reference (what we copy)

| Layer | Cowork today |
|-------|----------------|
| Detector | `90_antitamper` golden-hash scanner |
| Baseline | `%LOCALAPPDATA%\gsd-dlp\baseline\<version>\` + HMAC `manifest.sig` |
| Ledger | `dlp_antitamper_events` |
| User link | `user_id` → `dlp_users.user_id` (nullable, `ON DELETE SET NULL`) |
| Emit | BE `/log` insert → `emit_tamper()` → Hub `/alerts/events` |
| Alert | `alert_code=tamper`, `source_product=cowork` |
| Email | `anti_tamper_alert__security_admin_org_admin` (admins only today) |
| Config | `cowork_features.anti_tamper.{enabled, restore, interval_sec}` |

**Raven/Patron gaps:** no equivalent watcher, no product antitamper tables, no product-scoped Hub alerts, no developer recipient template.

---

## 3. Scope

### 3.1 In scope

| Product | Surfaces |
|---------|----------|
| **Raven** | Hooks/guards (damage-control, secret-guard, MCP-guard, etc.), plugin/skill install tree, on-disk enterprise policy / `.raven/manifest.json` (agent copy), signal senders (`stream-signal`, queue writers), install launchers, `VERSION`, requirements pins |
| **Patron** | Ghost-AI scanner package tree, rule packs / denylist / allowlist files, notify path (`hub_alerts` and siblings), agent bootstrap config presence (not secret values), VERSION / install launchers |

### 3.2 Out of scope (covered elsewhere)

- Authorized Hub portal policy edits → existing `config_change` alerts.
- Normal code commits / PRs → signoff / review flows.
- Runtime logs, caches, heartbeats, chat blobs, S3 object payloads (high churn; not hashed).

### 3.3 Explicit delete requirement

Deleting a **file or folder** under a protected Raven/Patron tree is a tamper event (`DELETED`). Same alert path as modify. Entire-install wipe is covered by delete detection where possible, plus **heartbeat-miss fallback** if the watcher dies before reporting.

---

## 4. Detection design

### 4.1 Lifecycle

```
Install / official upgrade
  → build baseline (hash protected files + golden copies + HMAC manifest)
  → upsert agent enrollment in DB (version, baseline_id, last_baseline_at)

Watch loop (every interval_sec, default 30)
  → rehash vs baseline
  → MODIFIED / DELETED  → optional restore + always emit event
  → ADDED              → report only (never delete stranger files)
  → write *_antitamper_events + emit Hub alert
```

### 4.2 Event types

| `event_type` | Meaning | Restore? |
|--------------|---------|----------|
| `MODIFIED` | Hash changed | Yes if `restore=true` |
| `DELETED` | File/folder missing | Yes if `restore=true` (recreate from golden) |
| `ADDED` | Unexpected new file in tree | Never auto-delete |
| `BASE_FAIL` | Baseline signature invalid / missing | No — critical alert |
| `WATCH_DIE` | Heartbeat miss / watcher gone (Phase 2) | N/A |

### 4.3 Protected-file rules (single source of truth)

Mirror Cowork `scanner.py` patterns:

- **Include:** `.py`, `.ps1`, `.sh`, `.json`, `VERSION`, `requirements.txt` (and product-specific equivalents)
- **Exclude dirs:** `__pycache__`, `.venv`, `.git`, `tests`, logs, caches, runtime home writable dirs
- **Exclude generated launchers** that regenerate every install (otherwise every reinstall alarms)

One include/exclude module per product — do not duplicate lists across install scripts and scanner.

### 4.4 Threat model (document in code + ops docs)

- Detection/audit, not a hard prevention boundary.
- Local Administrator can kill watcher, patch memory, or rewrite baseline + signature.
- HMAC raises cost; it does not stop determined local admins.

---

## 5. Version upgrade vs tamper

| Scenario | Baseline | DB | Alert? |
|----------|----------|-----|--------|
| Official installer / upgrade | Rebuild under `baseline/<new_version>/`; retire old golden tree per retention policy | Update enrollment: `agent_version`, `baseline_version`, `last_baseline_at` | **No** tamper alert |
| Developer edits/deletes files | Unchanged | Insert antitamper event | **Yes** |
| Developer edits baseline / breaks signature | N/A | Insert `BASE_FAIL` event | **Yes** (critical) |
| Unofficial zip overwrite without installer baseline rebuild | Hashes diverge from old baseline | Insert events | **Yes** (by design) |

**Rule:** Only the **official install/upgrade path** may call `build_baseline()` and update enrollment version fields. Manual folder copy is treated as tamper unless followed by official baseline rebuild.

### 5.1 DB enrollment fields (per agent seat / device)

Suggested table or columns on existing agent enrollment:

| Field | Type | Notes |
|-------|------|-------|
| `user_id` | UUID FK → users | Seat owner |
| `hostname` / `device_id` | string | Host |
| `product` | `raven` \| `patron` | |
| `agent_version` | string | From VERSION |
| `baseline_version` | string | Matches baseline dir |
| `baseline_id` | UUID / hash | Points at signed manifest id |
| `last_baseline_at` | timestamptz | |
| `anti_tamper_enabled` | bool | From org feature flag |
| `anti_tamper_restore` | bool | |
| `anti_tamper_interval_sec` | int | default 30 |
| `last_heartbeat_at` | timestamptz | For watcher-alive checks |

Historical antitamper **events** are append-only; enrollment is the mutable “current truth.”

---

## 6. Database design

### 6.1 Event tables

**Raven:** `raven_antitamper_events`  
**Patron:** `patron_antitamper_events`

Shared shape (Cowork-parity + messaging fields):

| Column | Type | Notes |
|--------|------|-------|
| `tamper_id` | UUID PK | |
| `timestamp` | timestamptz | server default now() |
| `hostname` | string NOT NULL | |
| `user_id` | UUID **FK → users.id**, nullable, `ON DELETE SET NULL` | Canonical user link |
| `user_email` | string nullable | Denormalized for notify if FK null later |
| `org_id` / `org` | per product convention | Tenant scope |
| `file_path` | text NOT NULL | Relative path; for folder delete use directory path |
| `event_type` | string(16) NOT NULL | MODIFIED / DELETED / ADDED / BASE_FAIL / WATCH_DIE |
| `old_hash` | string(64) nullable | |
| `new_hash` | string(64) nullable | |
| `restored` | bool | Attempted restore |
| `restore_ok` | bool nullable | |
| `agent_version` | string nullable | At time of event |
| `baseline_version` | string nullable | |
| `watcher_pid` | int nullable | |
| `check_interval_s` | int default 30 | |
| `email_sent` | bool default false | Optional delivery bookkeeping |
| `hub_emitted` | bool default false | Optional |

**Indexes:** `(user_id)`, `(timestamp)`, `(hostname)`, `(org_id, timestamp)`.

### 6.2 FK relationship (confirmed requirement)

```
*_antitamper_events.user_id  →  users.id
  nullable = true
  ondelete = SET NULL
```

- Always resolve and set `user_id` when the agent knows the enrolled user.
- Always store `user_email` for admin + developer mail even if FK later cleared.
- **Do not** `CASCADE` delete events when a user is removed — audit must survive.
- Matches Cowork (`dlp_antitamper_events.user_id`) and Patron blob audit (`actor_user_id`).

### 6.3 Version update in DB

On official upgrade:

1. Insert/update enrollment row with new `agent_version` / `baseline_version` / `last_baseline_at`.
2. Do **not** delete prior antitamper events.
3. Optionally mark prior baseline as `superseded_at` (retention / forensics).

---

## 7. Alert + email path

### 7.1 Taxonomy (recommended)

Do **not** overload Cowork-only `tamper` wording. Add:

| `alert_code` | `source_product` | Severity | Cadence | Roles |
|--------------|------------------|----------|---------|-------|
| `raven_tamper` | `raven` | critical | immediate | security_admin, org_admin (+ developer template) |
| `patron_tamper` | `patron` | critical | immediate | security_admin, org_admin (+ developer template) |

Register in Hub / raven_be taxonomy, product_sources, digests, RBAC.

### 7.2 Messaging templates

| Template code | Persona | Subject (sketch) |
|---------------|---------|------------------|
| `raven_anti_tamper_alert__security_admin_org_admin` | Security / Org Admin | `[CRITICAL] Raven Agent Tamper: [Device ID]` |
| `raven_anti_tamper_alert__developer` | Developer (actor) | `[CRITICAL] Raven Agent Change Detected on [Device ID]` |
| `patron_anti_tamper_alert__security_admin_org_admin` | Security / Org Admin | `[CRITICAL] Patron Agent Tamper: [Device ID]` |
| `patron_anti_tamper_alert__developer` | Developer (actor) | `[CRITICAL] Patron Agent Change Detected on [Device ID]` |

**Admin body (sketch):**  
Integrity check failed for Raven/Patron on device `[Device ID]` (`[User Email]`) at `[Timestamp]`. Path: `[File Path]`. Event: `[Event Type]`. Restored: `[Yes/No]`. Host flagged for audit.

**Developer body (sketch):**  
Protected Raven/Patron files were changed or removed on your device `[Device ID]` at `[Timestamp]`. Path: `[File Path]`. Admins have been notified. If this was unintentional, reinstall/repair the agent; if intentional, contact your security admin.

Wire into `event_map.json`, `inapp_map.json`, `catalog_data.json`, `inapp_catalog_data.json` (same path as Cowork `anti_tamper_alert__…`).

### 7.3 Recipients (confirmed requirement)

| Event | Security Admin | Org Admin | Developer (actor) |
|-------|----------------|-----------|-------------------|
| MODIFIED / DELETED / BASE_FAIL / WATCH_DIE | Email + in-app | Email + in-app | Email + in-app |
| Official upgrade baseline rebuild | No | No | No |

Use Hub messaging `include_actor` so the developer on the event receives the actor template; admins via role routing.

### 7.4 Emit helpers

- **Raven:** `emit_raven_tamper(org, event_id, detail, user, device, payload)` → `POST …/alerts/events` with `source_product=raven`, `alert_code=raven_tamper`.
- **Patron:** extend `patron_be/ghost-ai-scanner/src/notify/hub_alerts.py` with `emit_tamper(...)` → `source_product=patron`, `alert_code=patron_tamper` (same HTTP pattern as shadow-AI emits).

On DB insert success → emit (fail-open: log warning if Hub unreachable; still keep ledger row).

---

## 8. Feature configuration

| Product | Config key | Defaults |
|---------|------------|----------|
| Raven | `raven_features.anti_tamper.{enabled, restore, interval_sec}` | `enabled=false`, `restore=true`, `interval_sec=30` |
| Patron | `patron_features.anti_tamper.{enabled, restore, interval_sec}` | same |

- Portal / Hub org settings → invite / agent bootstrap (deep-merge like Cowork — do not replace whole map with partial stored JSON).
- Watcher installs/runs only when `enabled=true`.

---

## 9. Product-specific protected trees (v1 draft)

### 9.1 Raven

Protect (relative to agent install root), illustrative:

- Hook / guard scripts and Python modules that enforce policy
- Plugin skill packages that ship with Enterprise
- Agent-side manifest / policy snapshots
- Telemetry senders that ship events to Hub
- `VERSION`, dependency pin files, install/run launchers that are not regenerated each boot

Exclude: `.raven` runtime state that is meant to mutate, logs, audit queues content, caches, venvs, tests.

### 9.2 Patron

Protect:

- `ghost-ai-scanner` source/package used on the endpoint
- Rule / policy JSON consumed by the scanner
- Notify modules that call Hub
- Agent VERSION / install scripts (non-regenerated)

Exclude: scan result stores, heartbeats, S3 staging, logs, caches.

Final lists are locked in code as one module per product before ship.

---

## 10. End-to-end flows

### 10.1 Developer deletes Raven/Patron folder or files

```
Watcher scan → DELETED
  → optional restore from golden copy
  → INSERT antitamper_events (user_id FK, user_email, path, hashes)
  → emit raven_tamper / patron_tamper
  → email + in-app: Security Admin, Org Admin, Developer
```

### 10.2 Developer modifies protected file

```
MODIFIED → same as above (restore optional)
```

### 10.3 Official version update

```
Installer runs
  → build_baseline(new_version)
  → UPDATE enrollment (agent_version, baseline_version, last_baseline_at)
  → NO tamper alert
  → watcher continues against new baseline
```

### 10.4 Entire install removed / watcher killed (Phase 2)

```
Hub/agent enrollment: last_heartbeat_at stale beyond threshold
  → synthesize WATCH_DIE (or pending offline + integrity unknown)
  → alert admins (+ developer if identity known)
```

---

## 11. Implementation workstreams

| # | Workstream | Deliverables |
|---|------------|--------------|
| 1 | Protected-file contracts | Raven + Patron include/exclude modules + unit tests |
| 2 | Agent watchers | Baseline build, scan, restore, POST events |
| 3 | DB migrations | `raven_antitamper_events`, `patron_antitamper_events`, enrollment columns, FKs + indexes |
| 4 | Insert APIs | Authenticated agent log endpoints (or reuse product `/log` pattern) |
| 5 | Hub emit | `emit_*_tamper` on insert; fail-open |
| 6 | Taxonomy + messaging | New alert codes, 4 templates, event_map / inapp maps, tests |
| 7 | Feature flags | Hub org + invite deep-merge + agent bootstrap |
| 8 | Upgrade path | Installer calls re-baseline + enrollment update |
| 9 | Report Center (optional) | Antitamper counts for Raven/Patron effectiveness |
| 10 | Docs + ops | Threat model, how to repair agent, how upgrades work |

---

## 12. Testing plan

| Case | Expect |
|------|--------|
| Clean scan after baseline | No events |
| Modify protected file | MODIFIED event, restore if enabled, Hub emit, admin + developer templates resolve |
| Delete protected file/folder | DELETED event + alerts |
| Add unexpected file | ADDED event, file left in place |
| Edit baseline / break sig | BASE_FAIL, critical alert |
| Official upgrade | New baseline, enrollment version updated, **zero** tamper alerts |
| User row deleted | Event retained, `user_id` NULL, `user_email` still present |
| Feature `enabled=false` | Watcher not installed / no scan |
| Hub down | Event stored; emit warning logged; no crash |

---

## 13. Decisions locked for this plan

| Decision | Choice |
|----------|--------|
| Alert codes | New: `raven_tamper`, `patron_tamper` (not reuse Cowork-only `tamper` copy) |
| User FK | Yes — nullable FK to `users`, `ON DELETE SET NULL`, plus denormalized email |
| Version upgrade | Re-baseline + update enrollment DB; no false tamper |
| Folder/file delete | Always alert |
| Recipients | Security Admin + Org Admin **and** Developer (actor) |
| Restore default | `true` (Cowork-parity); org can disable |
| Watcher kill / heartbeat | Phase 2 |

---

## 14. Open items before coding

1. Exact install roots for Raven Enterprise agent and Patron agent on Win/macOS/Linux.
2. Which DB owns Raven antitamper rows (Hub Postgres vs raven_be) — recommend same DB that already stores Raven agent/seat identity for clean FKs.
3. Retention policy for superseded baselines and antitamper events.
4. Whether Phase 2 heartbeat is required for MVP or can follow v1 file integrity only.

---

## 15. Success criteria

- Admin receives critical email within near-real-time when a developer modifies or deletes protected Raven/Patron files/folders.
- Developer receives a corresponding notification.
- Official upgrades update baseline + DB version fields without generating tamper noise.
- Every event is joinable to a user when enrolled (`user_id` FK), and remains queryable after user deletion via denormalized email + SET NULL.
- Behavior and honesty of limits match Cowork anti-tamper documentation.

---

## 16. Related code references

| Area | Path |
|------|------|
| Cowork scanner | `dlp_installer/features/90_antitamper/src/scanner.py` |
| Cowork events model | `cowork_dlp_v2/DB/models/events.py` (`DlpAntitamperEvent`) |
| Cowork Hub emit | `cowork_dlp_v2/BE/notify/hub_alerts.py` (`emit_tamper`) |
| Cowork insert → emit | `cowork_dlp_v2/BE/main.py` (`dlp_antitamper_events`) |
| Hub taxonomy | `raven_be/app/alerts/taxonomy.py` (`tamper`) |
| Messaging template | `raven_be/app/services/messaging/catalog_data.json` (`anti_tamper_alert__…`) |
| Patron Hub emit pattern | `patron_be/ghost-ai-scanner/src/notify/hub_alerts.py` |
| Patron user FK pattern | `patron_be/ghost-ai-scanner/src/db/models_object_blob.py` (`actor_user_id`) |
