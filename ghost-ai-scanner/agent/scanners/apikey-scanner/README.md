# apikey-scanner

Detects hardcoded API keys and secrets across the git repositories on this
machine. Reports **detection metadata only** -- repo, file, line, pattern
type, git provenance (commit, author, timestamp). **The secret value
itself is never collected, stored, logged, printed, or exported. This is
the hard invariant the whole project is built around** -- see
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) section 1.1.

This tool reports **evidence, not a verdict**. Finding secrets always
exits `0`; there is no severity field and no `--fail-on-found` flag. What
you do with the findings is your call, made in your own systems.

## Known gap: working-tree scan only

This tool scans the current working tree plus `git blame` on matched
lines. It does **not** scan git history. A secret that was committed and
later deleted is still live in history and is **not detected** by this
tool in v1. Every report prints this limitation in its footer -- see
IMPLEMENTATION_PLAN.md section 4.4 for the full rationale and the planned
`--history` mode.

## The sensitive database

The findings database (`.apikey-scanner/findings.db` by default) states
exactly which file and line in which repo holds a live secret -- even
though it stores no secret bytes itself, that's a precise map an attacker
would want. It is created with `0600` permissions (best-effort on
platforms without POSIX bits) and its directory is auto-gitignored on
first run. Keep it off shared storage.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan one or more dev roots for git repositories, record findings
apikey-scanner scan --root D:\giggso_intern

# Print findings
apikey-scanner report --format table
apikey-scanner report --format jsonl > findings.jsonl
apikey-scanner report --format csv --confidence high,medium

# Compare two scans
apikey-scanner scans list
apikey-scanner diff --from 1 --to 2

# Allowlist a known false positive / accepted finding
apikey-scanner allowlist add <finding_id> --reason "test fixture"
apikey-scanner allowlist list

# List the pattern catalog
apikey-scanner patterns list --provider aws
```

A `scanner.toml` config file can set default roots, thresholds, and prune
dirs; pass it with `--config`. See `apikey_scanner/config.py` for every
field.

### Optional, off by default

- `--track-rotation` -- records a salted `secret_fingerprint` (HMAC with a
  random per-installation salt kept outside the database) so you can tell
  whether a still-open finding is the *same* secret as last scan or a
  rotated one. The salt lives at `.apikey-scanner/salt`; losing it just
  resets rotation-tracking continuity.
- `--hash-authors` -- replaces `author_name`/`author_email` with a salted
  hash, so the database doesn't carry real names/emails in plain text.

## What it detects

~58 patterns across cloud providers, VCS/CI tokens, AI provider keys,
payment processors, communications platforms, observability tools, SaaS
APIs, private key blocks, connection strings, and a gated generic
high-entropy fallback. Run `apikey-scanner patterns list` for the full,
current catalog -- it's data (`apikey_scanner/catalog/patterns.json`), so
it changes independently of releases.

Findings that are test-path or `.gitignore`d are reported, not suppressed
-- both are common places real credentials actually end up (see
IMPLEMENTATION_PLAN.md section 5.4).

## Development

```bash
pip install -e . ruff mypy pytest pytest-cov
ruff check apikey_scanner tests
mypy
pytest --cov=apikey_scanner --cov-report=term-missing
```

The most important test in this repository is
`tests/test_canary.py`: it plants known-fake secrets, runs a full scan
through every storage/export path, and asserts the raw secret bytes never
appear in any produced artifact. Any change that risks the section 1.1
invariant should make that test fail.
