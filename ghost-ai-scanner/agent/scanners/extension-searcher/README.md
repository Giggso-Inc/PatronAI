# Extension Searcher

Cross-platform browser extension inventory tool. Enumerates every installed
browser on the current user's account (Windows, Linux, macOS), every
profile within it, and every extension in each profile — version,
permissions, enabled state, and install origin.

Full design rationale, the complete browser path table, parser field
specs, and the risk/edge-case register live in [PLAN.md](PLAN.md). This
file is usage only.

## Install

Standard library only — no third-party runtime dependencies.

```bash
python -m venv .venv
.venv\Scripts\activate      # or: source .venv/bin/activate
pip install -e .
```

Or run directly without installing:

```bash
python -m extension_searcher
```

## Usage

```bash
# Human-readable table (default), grouped Browser -> Profile -> Extension
python -m extension_searcher

# JSON, written to a file
python -m extension_searcher --format json --output scan.json

# Only Chrome and Firefox
python -m extension_searcher --browser "Google Chrome" --browser "Mozilla Firefox"

# One engine only
python -m extension_searcher --engine gecko

# Include browser-bundled component extensions (PDF Viewer, Web Store, etc.)
python -m extension_searcher --include-builtin

# Flag extensions with near-total host access
python -m extension_searcher --risk
```

Run `python -m extension_searcher --help` for the full flag list.

**Exit codes:** `0` clean · `1` completed with entries in the JSON `errors[]`
list · `2` no browsers found · `3` bad usage / filters matched nothing.

## Scope (locked 2026-08-27 — see PLAN.md section 15)

1. Cross-OS: Windows, Linux, macOS — all first-class.
2. Dual output: human table and JSON are both first-class deliverables.
3. Safari and Internet Explorer are in scope, not optional extras.
4. Current user only — no `--all-users`, no elevation.

## Known limitations

- **No macOS host has verified the Safari parser or the `~/Library/...`
  path rows.** Every macOS path is marked `unverified` and surfaced in the
  JSON report's `unverified_paths`. See PLAN.md section 15.1.
- Safari and Internet Explorer records are always `confidence: "partial"`
  with empty `permissions` — a platform limitation (no manifest exists to
  read), not a parser gap. See PLAN.md section 5.3.
- `--deep` (`.xpi` archive verification), `--cache` (incremental scans),
  and `--extra-root` (portable/USB installs) are accepted by the CLI but
  not yet implemented — each logs a warning and is otherwise a no-op.
- Firefox / Firefox Developer Edition / Firefox Nightly channel
  disambiguation on a shared `profiles.ini` root uses a name/path
  heuristic (`dev-edition` / `nightly` substrings), not the more precise
  `installs.ini` install-hash mapping. See `gecko._profile_matches_channel`.

## Development

```bash
pip install -r requirements-dev.txt
pytest              # unit tests (fixture-driven, never touches your real profiles)
ruff check .
mypy
```
