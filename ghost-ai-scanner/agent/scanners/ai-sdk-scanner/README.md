# AI SDK Scanner

Scans a repository's dependency manifests and emits one row per declared
dependency: `repo_id, file_path, dependency_name, dependency_version,
commit_sha, scan_timestamp` — plus provenance fields that keep every value
honest (see below). **Every dependency is reported by default** —
`langchain` sits in the same output as `flask`, distinguished by
`category` and `is_ai_related`, not filtered out. Pass `--ai-only` to
restore the AI-filtered view.

**Findings are evidence of what code declares — a signal for review, not
a judgment that anything is a problem.** There is no severity field, no
risk score, and no fail-on-found flag anywhere in this tool. See
[PLAN.md](PLAN.md) section 1.1 for why that's a hard design constraint,
not an oversight. This framing was written for AI libraries specifically
but applies just as much now that every dependency is in scope: a
`fastapi` row is not a verdict on `fastapi` either.

Full design rationale, the catalog structure, parser field specs, and the
edge-case register live in [PLAN.md](PLAN.md). This file is usage only.

## Install

Standard library only — no third-party runtime dependencies.

```bash
python -m venv .venv
.venv\Scripts\activate      # or: source .venv/bin/activate
pip install -e .
```

Or run directly without installing:

```bash
python -m ai_sdk_scanner /path/to/repo
```

## Usage

```bash
# JSONL (default), one finding per line
python -m ai_sdk_scanner /path/to/repo

# Human-readable table, grouped by category
python -m ai_sdk_scanner /path/to/repo --format table

# Full JSON envelope (records + coverage + errors), to a file
python -m ai_sdk_scanner /path/to/repo --format json --output scan.json

# Override the derived repo_id (e.g. in a CI job with a detached checkout)
python -m ai_sdk_scanner /path/to/repo --repo-id my-org/my-repo

# Include transitive (lockfile-resolved) dependencies, not just direct ones
python -m ai_sdk_scanner /path/to/repo --include-transitive

# Attach the last commit that touched each matching manifest file
python -m ai_sdk_scanner /path/to/repo --with-file-commits

# Only AI/ML-catalog matches (the old, filtered default before this flag existed)
python -m ai_sdk_scanner /path/to/repo --ai-only
```

Run `python -m ai_sdk_scanner --help` for the full flag list.

## Whole-system scan

`--system` discovers every project on the machine and scans each one,
instead of taking a single repo path:

```bash
# Every fixed drive; human-readable, grouped per project
python -m ai_sdk_scanner --system --format table

# Specific roots only, with progress on stderr
python -m ai_sdk_scanner --system --roots D:\ --roots C:\Users\me\code --progress

# Just the user's home directory
python -m ai_sdk_scanner --system --home-only

# JSONL for a pipeline — identical row shape to single-repo mode
python -m ai_sdk_scanner --system --format jsonl --output findings.jsonl
```

A full scan of two drives on the development machine completes in about
**5 seconds** and reports every declared dependency (5,946 references
across 1,452 unique packages on that machine, of which 80 references /
23 packages were AI-classified). Projects with zero *reported*
dependencies are omitted unless you pass `--all-projects`; pass
`--ai-only` to go back to reporting only AI/ML-catalog matches, as in
single-repo mode. `SystemScanSummary` carries both totals and the
AI-specific subtotals (`ai_references`, `unique_ai_dependencies`,
`projects_with_ai_refs`) side by side, so "how much AI, relative to
everything else" is answerable directly from `--format json`.

**How a "project" is identified:** a directory containing `.git` (an
unambiguous boundary — discovery does not descend further, so submodules
and vendored clones are not listed separately), or failing that any
directory containing a dependency manifest. Container directories
(`Documents`, `Desktop`, `Downloads`, `OneDrive`, `$HOME`, drive roots)
are never treated as project roots, so a stray manifest in one does not
swallow every real project beneath it — but that stray manifest is also
not reported.

**What gets pruned:** OS directories (`Windows`, `Program Files`,
`ProgramData`), third-party package stores (`node_modules`,
`site-packages`, `anaconda3`, `.cargo`, `.m2`, `.gradle`, `.nuget`, …),
build output, and hidden directories. Without this, installed libraries'
own manifests would vastly outnumber your projects' — the counts are
reported as `dirs_visited` / `dirs_pruned` so the scope is auditable.

**Expect to find code you didn't write.** IDE installations and other
applications ship their own `package.json` — on the test machine, two
VS Code installs legitimately surfaced `@anthropic-ai/sdk` and `openai`.
Those are real references on the system; whether they're relevant is the
reviewer's call, which is exactly the framing in §1.1.

**Per-project file budget:** manifest discovery inside each project stops
after 20,000 files (`--max-files-per-project`, `0` for unlimited). One
real project on the test machine held 316,000 dataset files in `data/`
and took 56s alone; pruning `data/` by name would be wrong, so the walk
is budgeted instead. Truncated projects are flagged `walk_truncated` in
both the table and JSON output rather than reported as complete.

**Exit codes:** `0` clean · `1` one or more manifests failed to parse (see
the JSON `errors` list) · `2` target path not found/not a directory ·
`3` bad usage or an invalid `--catalog` file.

## What it reads

| Ecosystem | Files | Live-tested? |
|---|---|---|
| Python | `requirements*.txt`, `constraints.txt`, `pyproject.toml` (PEP 621, Poetry, PDM, uv), `Pipfile`, `setup.cfg`, `environment.yml` | ✅ against real repos |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | ✅ against real repos |
| Java / Kotlin (Maven) | `pom.xml` | ⚠️ synthetic fixtures only |
| Java / Kotlin (Gradle) | `build.gradle`, `build.gradle.kts` | ⚠️ synthetic fixtures only |
| Go | `go.mod` | ⚠️ synthetic fixtures only |
| Rust | `Cargo.toml` | ⚠️ synthetic fixtures only |
| .NET | `*.csproj`/`*.fsproj`/`*.vbproj`, `packages.config`, `Directory.Packages.props` | ⚠️ synthetic fixtures only |
| Ruby | `Gemfile` | ⚠️ synthetic fixtures only |
| PHP | `composer.json` | ⚠️ synthetic fixtures only |

`setup.py` is recognized but deliberately not parsed (its dependency list
can be arbitrary Python code) — it's reported in the JSON `coverage.
manifests_unparsed` list rather than silently skipped.

**The ⚠️ ecosystems have never been run against a real project.** A
machine-wide scan at build time found zero Java/Go/Rust/.NET/Ruby/PHP
projects to verify against — only Python and JavaScript had real repos on
hand, which is exactly why every bug this tool has actually shipped with
was found in those two. If you scan a real project in one of the ⚠️
ecosystems, its first output deserves a closer look than usual.

For a field-by-field breakdown of what each of the six new ecosystems
produces and exactly where each value comes from, see
[docs/ecosystem-expansion.md](docs/ecosystem-expansion.md).

## Collected fields

Every record carries the six specified fields plus all metadata derivable
from the manifest, the file, and git — **without any network call**. A
`None`/empty value always means "the source format does not express
this", never "we dropped it".

| Group | Fields |
|---|---|
| **Identity** | `repo_id`, `file_path`, `dependency_name`, `dependency_version`, `commit_sha`, `scan_timestamp` |
| **Name resolution** | `normalized_name` (the key the catalog matched on — group and dedupe on this, not the raw name), `extras` (`langchain[all]` → `all`) |
| **Version detail** | `version_spec_kind` (`pinned`/`range`/`unpinned`/`url`/`resolved`), `version_source` (`declared`/`resolved`), `version_constraints` (`>=1.0,<2` → `[">=1.0", "<2"]`), `environment_marker` |
| **Location** | `line_number`, `manifest_kind` |
| **Classification** | `ecosystem`, `category` (`unclassified` for the majority — the catalog identifies AI/ML libraries specifically), `is_ai_related` (the field to filter on), `dependency_group`, `is_direct`, `is_optional` |
| **Package source** | `declared_index_url` (private/alternate index — a real supply-chain signal), `vcs_url`, `vcs_ref`, `local_path` |
| **Supply chain** (lockfiles only) | `resolved_url`, `integrity` (content hash), `declared_license`, `has_install_script` (arbitrary code on install) |
| **Manifest fingerprint** | `manifest_sha256`, `manifest_mtime`, `manifest_size` — detect content change independently of git, which matters for uncommitted edits |
| **Git provenance** | `content_matches_commit`, `git_branch`, `git_remote_url` (raw, pre-normalization), `commit_date`, `commit_author`, plus `file_last_commit_sha`/`_date`/`_author` under `--with-file-commits` |
| **Project context** (`--system`) | `project_root`, `project_name`, `project_discovered_by` (`git_repo`/`manifest_only`) |
| **Auditability** | `raw_declaration`, `match_rule` — trace any row back to exactly why it was emitted |

`line_number` is **exact** for line-oriented formats (`requirements.txt`)
and **best-effort** for structured ones (TOML/JSON), where the parser
discards position data and the line is located by key search. It is
`None` when not determinable.

`file_last_commit_*` is often more useful than `commit_sha`: it answers
"when did this dependency last change, and who changed it", which is
usually a much older commit than HEAD.

## Known limitations

- **A manifest scan can miss real AI usage and can also over-report it.**
  Code that calls an AI API directly over plain HTTP produces zero catalog
  hits. A library declared in `requirements.txt` but never actually used
  still produces a row. Neither is a bug — see PLAN.md section 11.1.
- `dependency_version` is the **raw declared specifier**, verbatim — never
  a resolved guess. `^4.20.0` stays `^4.20.0`; check `version_spec_kind`
  (`pinned`/`range`/`unpinned`/`url`/`resolved`) to know what kind of value
  you're looking at.
- `boto3`, `requests`, `httpx`, `numpy`, `pandas`, `scipy`, and `pillow`
  are deliberately excluded from the catalog — they're too generic to
  imply AI usage from the manifest alone (see PLAN.md section 5.4). This
  is locked by a regression test.
- Firefox-style channel disambiguation doesn't apply here, but the
  equivalent honesty note is: `yarn.lock` entries are always treated as
  transitive (no direct/transitive marker exists in that file format by
  itself), and `pnpm-lock.yaml`'s nested transitive graph isn't parsed at
  all — only its top-level direct-dependency map is (a hand-rolled parser
  is used instead of a YAML library; see PLAN.md section 3.4).
- `content_matches_commit: false` on a record means that specific
  manifest file has uncommitted changes — `commit_sha` names a commit
  whose content may not match what was actually scanned.

## Development

```bash
pip install -r requirements-dev.txt
pytest --cov=ai_sdk_scanner   # 303 tests, 90% coverage as of this writing
ruff check .
mypy
```

Bugs found via testing during development, now locked in by regression
tests — each documented inline where it was fixed:

1. `git status --porcelain`'s first status column can be a literal
   leading space; blindly `.strip()`-ing the whole command output before
   parsing it line-by-line silently corrupted that column.
2. Python's `subprocess.run(text=True)` on Windows translates embedded
   `\n` in multi-line `input=` to `\r\n` on write, which broke
   `git check-ignore --stdin` for every path in a batch except the last.
3. A stray `package.json` in a container directory made whole-system
   discovery treat all of `$HOME` as a single project and stop
   descending, hiding every real project beneath it.
4. The manifest-walk file budget was only checked between directories, so
   a single directory with hundreds of thousands of files blew past it
   and still reported `truncated=False`.
5. `Path == Path.anchor` compares a `Path` to a `str` and is therefore
   always False, silently disabling the drive-root check (caught by
   `mypy`, not by a test).
6. The `langchain-` namespace rule caught `langchain-community` but not
   the bare `langchain` root package, so the most widely used AI
   framework on PyPI silently produced **zero** matches. Root packages
   are now pinned by name in a regression test.
7. `find_line_number` matched `"openai"` with quotes on both sides, which
   never matches PEP 621's `"openai>=1.0"` form where the name and its
   specifier share one quoted string.
8. The `yarn.lock` parser emitted a record on the `version` line, but
   `resolved` and `integrity` appear *after* it in a block — so both
   fields were always silently lost.
