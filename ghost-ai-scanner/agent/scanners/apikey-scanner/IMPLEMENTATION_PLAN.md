# IMPLEMENTATION PLAN — Hardcoded API Key Searcher

> **Project:** Hardcode API Key Searcher · **Org:** giggso · **Owner:** m.arunprasad@giggso.com
> **Status:** Plan — awaiting approval before implementation
> **Planned by:** Andie v6.4 (📘 Deep) · **Date:** 2026-09-01
> **Triad:** Fatima (AppSec Engineer, secret scanning at scale) · Andres (Static Analysis
> & Build Tooling) · Yamini (Provenance Data Engineer)
> · Lior (Devil's Advocate, Red Team)
> **Siblings:** `AI-SDK-Scanner`, `Extension Searcher` — conventions inherited deliberately.

---

## 1. Goal

Find every place on this machine where an API key or other secret appears to be
**hardcoded in source**, and emit one record per occurrence anchored to the exact
file, line, and commit that introduced it.

**The record:**

| Field | Meaning |
|---|---|
| `repo_id` | Which repository the finding came from (normalized remote, else path-derived) |
| `file_path` | Repo-relative path, posix separators |
| `line_number` | Line the match landed on |
| `column_start` / `match_length` | Where on the line, and how long — **not what** |
| `matched_pattern_type` | Which detector fired (`aws_access_key_id`, `generic_high_entropy`, …) |
| `provider` | `aws`, `stripe`, `github`, `generic`, … |
| `confidence` | `high` / `medium` / `low` — structural certainty, **not** severity |
| `detector` | `regex` or `entropy` |
| `commit_sha` | Commit that last touched that line (via blame) |
| `author_name` / `author_email` | Blame author of that line |
| `author_timestamp` | When that line was authored, ISO-8601 UTC |
| `scan_timestamp` | When this scan ran, ISO-8601 UTC |
| `finding_id` | Stable identity across scans (see §6) |

### 1.1 THE HARD INVARIANT

**The secret value is never collected, stored, logged, exported, printed, or hashed
into anything persisted.**

This is not a feature. It is the constraint the entire architecture is bent around,
and it is enforced **structurally and by test**, never by discipline alone:

1. **No field can hold it.** `Detection` and `Finding` dataclasses have no `value`,
   `match`, `snippet`, `preview`, or `line_text` field. Not "we don't populate it" —
   the field does not exist. Leaking becomes a schema change, which shows up in review.
2. **The match is reduced immediately.** The engine calls `m.span()` and discards the
   `Match` object in the same expression. The value never reaches a named local that
   outlives the loop iteration.
3. **No masked preview. Not even the last 4 characters.** Tempting, universally
   implemented elsewhere, and rejected here — last-4 plus provider plus length is
   enough to confirm a guessed key against a candidate list.
4. **Exceptions never carry the line.** Every raise site is passed `file_path` and
   `line_number` only. A traceback that dumps locals must find nothing.
5. **The canary test** (§11.2) greps every byte we write for planted secrets and fails
   the build if one appears. The invariant is regression-tested, not asserted.

> **Lior (Devil's Advocate):** "You say the value is never touched, then you plan a
> placeholder filter that has to look at `your_api_key_here`, and a fingerprint that
> has to be stable per-secret. Both read the value. Which is it?"
>
> **Resolution — an honest distinction the plan states plainly:** the invariant governs
> **egress**, not **in-process inspection**. Detection is impossible without reading
> bytes. What is forbidden is that any byte of the candidate reaches storage, output,
> logs, or memory that outlives the scan of that line. §6.2 handles the fingerprint;
> §5.3 handles the placeholder filter. Neither gets a pass.

### 1.2 Framing — evidence, not verdict

Inherited from `AI-SDK-Scanner` §1.1 and kept for the same reason.

- No `severity`, `risk_score`, `violation`, or `is_dangerous` field.
- Finding secrets exits `0`. **No `--fail-on-found` in v1** — a CI gate built on our
  JSONL keeps the judgment in the consumer's system, where it belongs.
- `confidence` describes how sure we are it *matched a pattern*, never how bad it is.
- Findings in test fixtures are **reported, not suppressed** (§5.4).

### 1.3 Non-goals

- Not a validator — **no network calls, ever**. We never ask AWS whether the key is
  live. That would transmit the secret, and it is the fastest way to break §1.1.
- Not a remediation tool. Read-only. Never modifies a scanned repo.
- Not a full-history scanner in v1 (§4.4 — a known, documented gap).
- Not a policy engine.

---

## 2. Why this is feasible

Most secrets are structurally self-identifying: AWS keys start `AKIA` and are exactly
20 characters; GitHub PATs start `ghp_` and carry a CRC32 checksum; Stripe live keys
start `sk_live_`; private keys open with a `-----BEGIN` armor line. That makes the
high-confidence half of the problem a table lookup.

The rest — a 32-char hex string assigned to `API_KEY` — has no signature, only
**shape plus context**. That half is entropy scoring gated on the identifier next to
it, and it is where all the false positives live (§5).

No package manager runs. No dependency installs. No network is touched.

---

## 3. Architecture

### 3.1 Pipeline

```
Config (roots)                                          ┌─> SQLite store ─> diff (new/resolved)
      │                                                 │
      v                                                 │
Repo Discovery ─> File Walk ─> Line Scan ─> FP Filters ─┤
 (find .git)      (prune)      regex ∪              │   └─> report (table|json|jsonl|csv)
                               entropy              │
                                                    v
                                          Git Blame (batched -L per file)
```

### 3.2 The one design rule

**The pattern catalog is DATA, never code.** Adding a newly-launched provider's key
format must be a one-object edit to `patterns.json` — never a new `if`, never a new
module. This is carried over from both siblings, where the same decision collapsed
~49 browsers into 4 parsers.

*The one permitted exception:* a pattern may name a **validator** (`"validate":
"github_crc32"`). Validators are pure functions in a small registry. Reusing an
existing validator is a data edit; adding a genuinely new checksum algorithm is a
rare code change. This is stated so the rule does not quietly erode.

### 3.3 Module layout

```
apikey_scanner/
├── __init__.py
├── __main__.py               # python -m apikey_scanner
├── cli.py                    # argparse, subcommands, exit codes
├── config.py                 # roots, thresholds, caps — TOML/JSON, with defaults
├── models.py                 # dataclasses ONLY. No field may hold a secret (§1.1).
├── catalog/
│   ├── __init__.py
│   ├── loader.py             # load + validate + compile; builds the union regex
│   ├── patterns.json         # THE CATALOG (data)                      §4
│   └── validators.py         # named checksum fns: github_crc32, aws_key_id, luhn…
├── discovery.py              # walk dev roots -> repo roots (stop at .git)
├── walk.py                   # per-repo file walk, prune, binary/size/minified gates
├── detect/
│   ├── __init__.py
│   ├── engine.py             # single-pass union-regex scan per line
│   ├── entropy.py            # Shannon entropy, charset-aware thresholds
│   ├── context.py            # identifier proximity, assignment/arg detection
│   └── filters.py            # false-positive suppression                §5
├── git_context.py            # repo_id, HEAD sha, dirty, tracked  (port from sibling)
├── blame.py                  # batched `git blame -L a,a -L b,b --porcelain`
├── store/
│   ├── __init__.py
│   ├── schema.sql            # DDL (data, not string-concatenated Python)
│   ├── sqlite_store.py       # upsert findings, scan rows, allowlist
│   └── diff.py               # new / persisting / resolved between two scans
├── report/
│   ├── __init__.py
│   ├── structured.py         # jsonl (primary), json, csv
│   └── table.py              # human-readable
└── errors.py
tests/
├── fixtures/
│   ├── canaries/             # planted, structurally-valid FAKE secrets   §11.2
│   ├── repos/                # synthetic git repos built in tmpdir
│   └── false_positives/      # lockfiles, minified js, UUIDs, placeholders
└── test_*.py
```

---

## 4. Detection engine

### 4.1 Catalog entry shape

```json
{
  "id": "aws_access_key_id",
  "name": "AWS Access Key ID",
  "provider": "aws",
  "kind": "api_key",
  "regex": "\\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[A-Z0-9]{16})\\b",
  "capture_group": 1,
  "confidence": "high",
  "requires_identifier_proximity": false,
  "min_entropy": null,
  "validate": null,
  "references": ["https://docs.aws.amazon.com/..."]
}
```

`confidence` is derived from structure, not guesswork:

- **high** — unique prefix and/or checksum. Near-zero FP rate. (`AKIA…`, `ghp_…`,
  `sk_live_…`, `xoxb-…`, `-----BEGIN … PRIVATE KEY-----`)
- **medium** — recognisable shape, no prefix. (`AIza…` Google, JWT `eyJ…`, connection
  strings with an inline password)
- **low** — generic. Requires identifier proximity **and** entropy to fire at all.

### 4.2 Seed coverage (v1 target ≈ 70 patterns)

| Group | Examples |
|---|---|
| Cloud | AWS key id + secret, GCP API key, GCP service-account JSON, Azure storage key + connection string, DigitalOcean `dop_v1_`, Heroku, Cloudflare, OCI |
| VCS / CI | GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`, GitLab `glpat-`, Bitbucket, npm `npm_`, PyPI `pypi-AgEI…`, Docker Hub, JFrog, Terraform Cloud |
| AI | OpenAI `sk-`/`sk-proj-`, Anthropic `sk-ant-`, HuggingFace `hf_`, Cohere, Replicate |
| Payments | Stripe `sk_live_`/`rk_live_`/`pk_live_`, Square, PayPal/Braintree, Razorpay |
| Comms | Slack `xox[baprs]-`/`xapp-`, Twilio `SK…`/`AC…`, SendGrid `SG.`, Mailgun, Discord, Telegram |
| Observability | Datadog, New Relic, Sentry DSN, PagerDuty, Segment |
| SaaS | Notion `secret_`, Airtable, Linear, Atlassian, Asana, Shopify `shpat_`, Algolia |
| Structural | JWT, `-----BEGIN (RSA/EC/DSA/OPENSSH/PGP) PRIVATE KEY-----`, htpasswd, `Authorization: Bearer …`, basic-auth credentials embedded in URLs |
| Connection strings | `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://` with inline credentials |
| Generic | `generic_high_entropy` (entropy + proximity, §4.3) |

### 4.3 Entropy fallback — and why it is gated

Shannon entropy alone on a whole codebase produces an unusable FP storm: minified JS,
base64 images, git SHAs, and integrity hashes are all high-entropy.

The generic detector fires **only when all four hold**:

1. Candidate length ≥ 20 (configurable).
2. Charset-aware entropy above threshold — base64 ≥ 4.5 bits/char, hex ≥ 3.0.
   Thresholds are config, not constants, because they will need tuning (§13, phase 6).
3. **Identifier proximity** — the candidate is the right-hand side of an assignment
   (`=`, `:`, `=>`, `:=`) whose left-hand identifier matches
   `key|token|secret|password|passwd|pwd|auth|credential|api[_-]?key|access|private|bearer|signature|salt|cert|passphrase`,
   **or** it is a string argument to a call whose name matches the same set.
4. It survives every filter in §5.

Identifier proximity is the load-bearing gate. Without it, this detector is noise.

### 4.4 Known gap: history-only secrets

Working-tree scanning **cannot** find a key that was committed and later deleted —
which is still live in git history and still leaked. This is a real, deliberate v1
limitation, stated in `README.md` and `--help` in plain words, not buried.

> **Lior:** "So the tool's headline promise is 'find hardcoded keys' and it silently
> misses the single most common real incident — the key someone already 'removed'."
>
> **Resolution:** it is not silent. Every report footer prints
> `working-tree scan only — secrets removed from HEAD but present in history are NOT covered`.
> A `--history` mode over `git rev-list --all` blobs is designed for v2 and scoped in
> §14, not hand-waved.

---

## 5. False-positive suppression

This is where secret scanners live or die. Ordered cheapest-first.

### 5.1 File-level gates (before any regex runs)

| Gate | Default | Rationale |
|---|---|---|
| Binary sniff | NUL byte in first 8 KB → skip | Images, .pyc, .dll |
| Size cap | 5 MB | Beyond this it's data, not source |
| Lockfiles | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`, `go.sum`, `composer.lock` → **high-confidence patterns only, entropy detector off** | Wall-to-wall integrity hashes. A real `AKIA` in one still fires. |
| Minified / bundled | `*.min.js`, `*.min.css`, `*.bundle.*`, `*.map` → skip | Entropy meaningless |
| Long-line guard | any single line > 5000 chars → skip that line | Catches un-suffixed minified files |
| Pruned dirs | `node_modules`, `site-packages`, `dist-packages`, `.venv`, `venv`, `vendor`, `.git`, `dist`, `build`, `target`, `.next`, `__pycache__`, `.mypy_cache`, `.ruff_cache`, `.pytest_cache` | Ported verbatim from `system_scan.py` — third-party code is pruned, not deprioritized |

### 5.2 Match-level filters

- **Placeholders** — `your_`, `<your`, `example`, `changeme`, `placeholder`, `dummy`,
  `sample`, `redacted`, `xxxx`, `INSERT_`, `TODO`, `FIXME`, `foo`/`bar`, all-same-char,
  strictly sequential (`abcdef…`, `123456…`).
- **Indirection, not literals** — `${ENV_VAR}`, `{{ template }}`, `%s`, `os.environ[…]`,
  `process.env.…`, `System.getenv(…)`, `config.get(…)`. These are the *correct*
  pattern; flagging them trains people to ignore the tool.
- **Structural non-secrets** — UUIDs (own low-confidence type, not suppressed
  outright), 40-char git SHAs in changelogs, `data:image/…;base64,`, SVG path data,
  CSS colour runs, `sha256-`/`sha512-` SRI hashes.
- **Checksum validators** — where the format carries one (GitHub CRC32, AWS key-id
  base32 account decode), a failed checksum drops the match. Highest-value filter
  available, and it needs no knowledge of the value beyond the check itself.

### 5.3 The placeholder filter and the invariant

The filter is a **pure predicate**: `is_placeholder(candidate: str) -> bool`. It takes
the candidate, returns a bool, and the caller keeps only the bool. Enforced by:

- signature returns `bool` — mypy `--strict` will not let a `str` escape;
- the function does not log, and `filters.py` imports no logger;
- the canary test (§11.2) covers this path.

### 5.4 What we deliberately do NOT suppress

- **Test files and fixtures.** Real credentials get committed to tests constantly.
  We set `in_test_path: true` as metadata and report it. Consumer decides.
- **`.gitignore`d files.** A gitignored `.env` is exactly where live keys sit, and
  it is *not* in git. We scan it, set `is_git_tracked: false`, and blame returns null.
  This is one of the highest-value cases in the whole tool, and the naive
  "skip ignored files" shortcut would delete it.

---

## 6. Identity, dedup, and the fingerprint problem

### 6.1 `finding_id` — stable identity with zero secret input

Requirement: the same hardcoded key must keep the same id across scans even when the
file is reformatted and its line number drifts. Naive options both fail:

- `hash(repo, file, line)` → every edit above the line invents a "new" finding.
- `hash(secret)` → violates §1.1.

**Design — context anchor with the match span excised:**

```
anchor      = line text, with [column_start, column_start+match_length) replaced by "\x00"
              then whitespace-normalized
finding_id  = sha256(repo_id | file_path | pattern_id | anchor | ordinal)[:32]
```

The anchor is the *surrounding code* (`AWS_KEY = "\x00"`), which is stable under
reformatting and reordering, and by construction contains **not one byte** of the
secret. `ordinal` disambiguates identical lines in one file.

### 6.2 `secret_fingerprint` — opt-in, salted, off by default

Only one question needs the value: *"is this the same key as last scan, or was it
rotated?"* That is genuinely useful and genuinely dangerous.

- **Default: the column is `NULL`. No hash function is ever called on the value.**
- `--track-rotation` enables `HMAC-SHA256(installation_salt, value)[:16]`.
- `installation_salt` is 32 random bytes generated on first use, stored in
  `.apikey-scanner/salt` (mode `0600`, gitignored), **never** in the findings DB and
  never exported.

> **Lior:** "An unsalted hash of a short key is crackable in seconds, and a shared
> salt makes fingerprints correlatable across machines — now you've built a
> distributed index of who holds which secret."
>
> **Resolution:** salt is per-installation and random, so fingerprints are meaningless
> off-box; it lives outside the DB, so leaking the DB does not enable cracking; and
> the whole feature is off unless explicitly requested. If the salt file is lost,
> rotation tracking resets — an acceptable, documented failure mode.

---

## 7. Git provenance

### 7.1 Discovery and `repo_id`

Walk configured roots, identify a repo by a `.git` entry, **stop descending** on match
(sibling pattern — prevents nested vendored repos exploding the walk).

`repo_id` = normalized `origin` remote (`git@github.com:org/repo.git` and
`https://github.com/org/repo.git` both → `github.com/org/repo`), falling back to
`local/<dirname>-<sha256(abspath)[:8]>` when there is no remote. Port
`normalize_remote_url` from `AI-SDK-Scanner/ai_sdk_scanner/git_context.py` unchanged.

### 7.2 Blame — batched, not per-finding

Naive: one `git blame -L n,n` per finding = thousands of subprocesses.

**Design:** group findings by file, emit **one** blame per file carrying every needed
range — `git blame --porcelain -L 12,12 -L 88,88 -L 301,301 -- path`. Git accepts
repeated `-L`. This collapses N calls to one per file.

Parse `--porcelain`: `author`, `author-mail`, `author-time`, `author-tz`, and the
boundary SHA. Convert `author-time` to ISO-8601 UTC.

### 7.3 `provenance_state` — four honest outcomes

| State | Meaning | `commit_sha` |
|---|---|---|
| `committed` | Line is in HEAD and blames cleanly | real sha |
| `uncommitted_change` | Blame returns all-zero sha — edited, not committed | `null` |
| `untracked` | File is not in git (incl. gitignored `.env`) | `null` |
| `not_a_repo` | Scanned outside any repo | `null` |

Never fabricate HEAD's sha for a line git could not attribute. A null that means
"we don't know" beats a plausible wrong answer.

### 7.4 Author email is PII

`author_email` is a real person's address. `--hash-authors` replaces name and email
with `sha256(salt|email)[:16]`, preserving "same author" grouping without storing the
identity. Off by default; documented in `README.md`.

### 7.5 Windows specifics

Subprocess with a 15 s timeout (sibling precedent); `text=True` with explicit
`encoding="utf-8", errors="replace"`; `.rstrip("\r\n")` not `.strip()` (the sibling hit
a real bug here — porcelain lines can start with a meaningful space); all stored paths
converted to posix separators, repo-relative.

---

## 8. Storage schema

```sql
CREATE TABLE scan (
  scan_id         INTEGER PRIMARY KEY,
  scan_timestamp  TEXT NOT NULL,          -- ISO-8601 UTC
  tool_version    TEXT NOT NULL,
  catalog_version TEXT NOT NULL,
  host            TEXT,
  roots_json      TEXT NOT NULL,
  repos_scanned   INTEGER, files_scanned INTEGER, files_skipped INTEGER,
  findings_total  INTEGER, duration_ms  INTEGER
);

CREATE TABLE finding (
  finding_id            TEXT PRIMARY KEY,     -- §6.1, no secret input
  repo_id               TEXT NOT NULL,
  repo_path             TEXT NOT NULL,
  file_path             TEXT NOT NULL,        -- repo-relative, posix
  line_number           INTEGER NOT NULL,
  column_start          INTEGER NOT NULL,
  match_length          INTEGER NOT NULL,     -- length only. NEVER the value.
  matched_pattern_type  TEXT NOT NULL,
  pattern_id            TEXT NOT NULL,
  provider              TEXT NOT NULL,
  confidence            TEXT NOT NULL,        -- high|medium|low
  detector              TEXT NOT NULL,        -- regex|entropy
  entropy_bits          REAL,                 -- null for regex hits
  commit_sha            TEXT,
  author_name           TEXT,
  author_email          TEXT,
  author_timestamp      TEXT,
  provenance_state      TEXT NOT NULL,        -- §7.3
  is_git_tracked        INTEGER NOT NULL,
  is_gitignored         INTEGER NOT NULL,
  in_test_path          INTEGER NOT NULL,
  first_seen_scan_id    INTEGER NOT NULL REFERENCES scan(scan_id),
  last_seen_scan_id     INTEGER NOT NULL REFERENCES scan(scan_id),
  status                TEXT NOT NULL,        -- open|resolved|allowlisted
  resolved_scan_id      INTEGER REFERENCES scan(scan_id),
  secret_fingerprint    TEXT                  -- NULL unless --track-rotation (§6.2)
);

CREATE TABLE finding_observation (      -- per-scan sighting; line drift lives here
  finding_id  TEXT NOT NULL REFERENCES finding(finding_id),
  scan_id     INTEGER NOT NULL REFERENCES scan(scan_id),
  line_number INTEGER NOT NULL,
  PRIMARY KEY (finding_id, scan_id)
);

CREATE TABLE allowlist (
  finding_id TEXT PRIMARY KEY, reason TEXT NOT NULL,
  added_by TEXT, added_at TEXT NOT NULL
);

CREATE INDEX idx_finding_repo   ON finding(repo_id, status);
CREATE INDEX idx_finding_status ON finding(status, last_seen_scan_id);
```

**Diff semantics:** after scan N — `first_seen_scan_id = N` → **new**;
`last_seen_scan_id < N` and `status='open'` → **resolved** (set `status='resolved'`,
`resolved_scan_id = N`); a resolved finding_id seen again → **reopened**.

**The DB is sensitive by location.** It states exactly which file and line in which
repo holds a live AWS key. That is a treasure map even with no values in it. It is
created `0600`, written to `.apikey-scanner/` and added to `.gitignore` by the tool
on first run, and `README.md` says this in the first section rather than a footnote.

---

## 9. CLI surface

```
apikey-scanner scan     [--root PATH ...] [--config FILE] [--jobs N]
                        [--track-rotation] [--hash-authors] [--no-entropy]
apikey-scanner report   [--format table|json|jsonl|csv] [--new-only] [--repo ID]
                        [--confidence high,medium] [--since SCAN_ID]
apikey-scanner diff     --from SCAN_ID --to SCAN_ID
apikey-scanner allowlist add FINDING_ID --reason TEXT | list | remove FINDING_ID
apikey-scanner patterns list [--provider P]
apikey-scanner scans    list
```

**Exit codes:** `0` success (regardless of findings — §1.2) · `1` internal error ·
`2` bad usage/config. There is no findings-based exit code in v1.

**Config file** (`scanner.toml`) — roots, extra prune dirs, entropy thresholds, size
cap, enabled/disabled pattern ids, db path. CLI flags override.

---

## 10. Performance

Target: **≈50 repos across configured dev roots in under 60 s.**

1. **One union regex, not 70.** All high-confidence patterns compile into a single
   alternation with named groups — one pass per line instead of 70. Watch Python's
   100-group ceiling: shard into batched unions of ≤ 40 patterns.
2. **Regex safety is mandatory.** No nested quantifiers, no unbounded `.*`, every
   pattern anchored or bounded. A dedicated test feeds adversarial input to each
   pattern under a per-pattern timeout to catch catastrophic backtracking before it
   hangs a real scan.
3. **Prune before descending** (§5.1), never filter after.
4. **`ThreadPoolExecutor` across repos** — the work is subprocess- and IO-bound, so
   the GIL is not the constraint. The sibling took a full two-drive scan from 92 s to
   5 s this way.
5. **Batched blame** (§7.2) — the single largest win.
6. **Per-repo file budget** with a fair-share cap, so one pathological directory
   cannot consume the whole budget (a real bug the sibling shipped and then fixed).
7. Blame runs **only for lines that survived every filter**, never speculatively.

---

## 11. Testing

### 11.1 Standard bar (matched to siblings)

`ruff` + `mypy --strict` clean · pytest ≥ **90 %** coverage · synthetic fixtures for
determinism · a `live` marker, deselected by default, for real-machine scans.

### 11.2 The canary test — the most important test in the project

```
1. Fixture repo contains planted, structurally valid, PUBLICLY KNOWN-FAKE secrets
   (e.g. AWS's own doc example AKIAIOSFODNN7EXAMPLE), one per pattern family.
2. Run a full scan: SQLite write, all four export formats, table output,
   stdout, stderr, and the log file at DEBUG.
3. Read back every artifact AS RAW BYTES and assert each canary string
   appears ZERO times.
4. Also assert the scan FOUND them — proving the test is scanning
   a populated corpus, not an empty one.
```

This runs on every commit. It is the only mechanism that catches a future
contributor adding a well-meaning `snippet` field.

### 11.3 Additional suites

- **Precision corpus** — lockfiles, minified bundles, UUIDs, base64 images, git SHAs,
  `${ENV}` indirection. Asserts **zero** findings. Guards §5 against regression.
- **Recall corpus** — one valid sample per catalog pattern; every pattern must fire.
- **Git fixtures** — real `git init` + commits in `tmp_path`: committed line, dirty
  line, untracked file, gitignored `.env`, repo with no commits, repo with no remote.
  Each asserts the correct `provenance_state` from §7.3.
- **Identity stability** — reformat a fixture file (shift lines, change indentation);
  assert `finding_id` is unchanged and the finding is *not* reported as new.
- **Catalog validation** — every entry compiles, has required fields, unique `id`,
  named validator exists.

---

## 12. Pre-mortem — how this ships broken

| # | Failure | Likelihood | Mitigation |
|---|---|---|---|
| 1 | A secret reaches the DB via a field added later "for context" | **High** without guards | §1.1 structural absence + §11.2 canary test in CI |
| 2 | A traceback dumps a local holding the value | Medium | Span-and-discard (§1.1.2); no logger in `filters.py`; canary test reads stderr |
| 3 | FP flood → users stop reading output → tool is dead | **High** | §5 layered filters; phase 6 is dedicated tuning against real roots with a measured precision number |
| 4 | Findings churn as "new" on every reformat | Medium | §6.1 context anchor; explicit stability test |
| 5 | Scan is too slow to run regularly | Medium | §10; blame only post-filter |
| 6 | DB leaks → attacker gets a precise map to live keys | Low / high impact | `0600`, auto-gitignore, README front-and-centre, no values stored |
| 7 | `--track-rotation` salt committed to git | Low / high impact | Salt outside DB dir, auto-gitignored, mode `0600` |
| 8 | Catastrophic regex backtracking hangs a scan | Medium | §10.2 adversarial-input timeout test per pattern |
| 9 | Author emails treated as ordinary telemetry | Medium | §7.4 `--hash-authors`; PII called out in README |
| 10 | History-only secrets missed, users assume coverage | **High** | §4.4 — printed in every report footer, not just docs |

---

## 13. Phased delivery

| Phase | Scope | Done when |
|---|---|---|
| **0** | `raven-init` manifest (missing here — both siblings have one), `pyproject.toml`, package skeleton, ruff/mypy/pytest config | `python -m apikey_scanner --version` runs; Raven guards active |
| **1** | `models.py`, catalog loader, `patterns.json` (high-confidence only), union-regex engine, **canary test** | Canary test green with real detections |
| **2** | `discovery.py`, `walk.py`, `detect/filters.py`, precision corpus | Zero findings on the FP corpus |
| **3** | `git_context.py` (ported), `blame.py` batched, `provenance_state` | All six git fixtures assert correctly |
| **4** | `store/` — schema, upsert, diff, allowlist | Two-scan test shows new/resolved/reopened |
| **5** | `cli.py`, all four reporters, config file | Full scan of these three Patron projects |
| **6** | Entropy detector + **FP tuning against real dev roots** | Measured precision reported in README; thresholds locked |
| **7** | Catalog to ~70 patterns, README, `--help` framing, docs | Coverage ≥ 90 %, ruff + mypy strict clean |

Phase 6 is the one most likely to be underestimated. Every published scanner's
reputation is decided there, not in the regex table.

---

## 14. Locked decisions (ADR-style)

| # | Decision | Rationale | Reversible? |
|---|---|---|---|
| 1 | Scope = git repos auto-discovered under configured dev roots | Real provenance for every finding; avoids multi-hour full-drive walks | Yes — sibling added `--system` later |
| 2 | Working tree + batched blame, not full history | Fast, accurate for present keys; history is v2 | Yes — §4.4 designs it |
| 3 | Pure stdlib: curated regex + gated entropy | Auditable, no external binary ever touches the secret, we own the rules | Yes |
| 4 | SQLite + JSON/CSV export | Dedup + scan-over-scan history with zero infra | Yes — store is an interface |
| 5 | **Secret value never egresses; no masked preview** | §1.1 — the project's reason to exist | **No** |
| 6 | No network calls, no key validation | Validation transmits the secret | **No** |
| 7 | `secret_fingerprint` opt-in, salted, salt outside the DB | Rotation tracking without a crackable index | Yes (as a flag) |
| 8 | No `--fail-on-found`, findings exit `0` | Evidence, not verdict — judgment stays with the consumer | Yes, but see §1.2 |
| 9 | Test-path and gitignored findings reported, not suppressed | Both are where real keys actually are | Yes |

---

## 15. Open questions for the owner

1. **Dev roots** — confirm the default set. Proposed: `D:\giggso_intern` plus any
   additional roots you name. Anything under `C:\Users\Arun Prasad\` to include?
2. **`--hash-authors`** — default off (real names/emails stored) or default on?
   Matters if this DB is ever shared beyond your machine.
3. **Package/CLI name** — `apikey_scanner` / `apikey-scanner`, matching the sibling
   `ai_sdk_scanner` / `ai-sdk-scanner` convention. Confirm or rename.
4. **File name** — siblings use `PLAN.md`; this is `IMPLEMENTATION_PLAN.md` as you
   asked. Say the word and I will align it to the sibling convention.

---

*Plan authored by Andie v6.4 (📘 Deep). No implementation performed. Awaiting approval.*
