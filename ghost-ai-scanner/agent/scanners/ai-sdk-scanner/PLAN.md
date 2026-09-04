# PLAN — AI SDKs & Frameworks Scanner

> **Project:** AI-SDK-Scanner · **Org:** giggso · **Owner:** m.arunprasad@giggso.com
> **Status:** Plan — awaiting approval before implementation
> **Planned by:** Andie v6.4 (📘 Deep) · **Date:** 2026-08-31
> **Triad:** Amara (OSS Compliance & SBOM Lead) · Andres (Static Analysis / Build Tooling)
> · Yamini (Provenance Data Engineer) · Lior (Devil's Advocate, AppSec)

---

## 1. Goal

Scan a source repository, read its dependency manifests, and emit one row for every
**AI/ML library reference** found — anchored to the exact file and commit it came from.

**The record (as specified):**

| Field | Meaning |
|---|---|
| `repo_id` | Which repository this finding came from |
| `file_path` | The manifest file the reference was declared in, repo-relative |
| `dependency_name` | The AI library's package name, normalized |
| `dependency_version` | The version **as declared in that file** (see §6 — this is usually a *specifier*, not a resolved version) |
| `commit_sha` | The commit the scan was anchored to |
| `scan_timestamp` | When the scan ran, ISO-8601 UTC |

### 1.1 Framing — this is evidence, not a verdict

**This is the single most important design constraint in the project.**

The output states *"this repo references this AI library, here, at this commit."* It does
**not** state that this is a problem, a risk, or a policy violation. That framing is carried
into the code itself:

- **No** `risk_score`, `severity`, `violation`, `flagged`, or `is_dangerous` fields.
- **No** pass/fail exit code based on findings. Finding AI libraries is exit `0`.
- `category` (e.g. `llm_sdk`, `vector_db`) exists as **descriptive** metadata only — it says
  what kind of library it is, never how bad it is.
- README and `--help` state the framing in plain words, so a reader who only sees the output
  cannot mistake it for a judgment.

> **Lior (Devil's Advocate):** "Neutral framing is easy to write in a plan and easy to lose
> in implementation. The moment someone adds `--fail-on-found` for a CI gate, this becomes a
> policy tool and the framing is dead. Decide now whether that flag is ever allowed."
> **Resolution:** it is not, in v1. A consumer who wants a gate can build one on the JSONL —
> that keeps the judgment in *their* system, where it belongs, and out of this tool.

### 1.2 Non-goals

- Not a vulnerability/CVE scanner — no advisory lookups, no severity.
- Not a license scanner.
- Not a code scanner: v1 reads **dependency manifests**, not `import` statements (see §11.1).
- No network calls. No registry API lookups. Offline by design.
- Does not modify the scanned repository, ever. Read-only.

---

## 2. Why this is feasible

Every ecosystem declares its dependencies in a small number of well-known, machine-readable
files (`requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`, …). The scan is
therefore: **find those files → parse them → match names against a catalog of known AI
libraries → attach git provenance.**

No package manager needs to run. No dependency needs to be installed. No network is touched.

---

## 3. Architecture

### 3.1 Pipeline

```
Git Context  ──┐
               ├──> Manifest Discovery ──> Format Parser ──> Catalog Match ──> Record ──> Output
AI Catalog   ──┘        (walk repo)       (one per format)   (name lookup)              (jsonl|csv|json|table)
```

### 3.2 The one design rule

**The AI-library catalog is DATA, never code.** Adding a newly-released AI SDK must be a
one-line edit to a data file — never a code change, never a new `if` branch. Same for the
manifest-format table.

This is carried over deliberately from the Extension Searcher project in this workspace,
where the equivalent decision (a declarative browser path table) was the thing that made
~49 browsers collapse into 4 parsers.

### 3.3 Module layout

```
ai_sdk_scanner/
├── __init__.py
├── __main__.py            # python -m ai_sdk_scanner
├── cli.py                 # argparse, exit codes, output dispatch
├── models.py              # DependencyRef, ScanRecord, ScanReport. Dataclasses only.
├── catalog/
│   ├── __init__.py
│   ├── loader.py          # loads + validates the catalog, normalizes names
│   └── ai_libraries.json  # THE CATALOG (data). See §5.
├── discovery.py           # walk the repo, find manifest files, apply ignore rules
├── git_context.py         # repo_id, commit_sha, dirty state, per-file last commit
├── parsers/
│   ├── __init__.py
│   ├── base.py            # DependencyRef contract every parser returns
│   ├── python_requirements.py   # requirements*.txt, constraints.txt
│   ├── python_pyproject.py      # PEP 621 + Poetry + PDM/uv
│   ├── python_misc.py           # Pipfile, setup.cfg, environment.yml
│   ├── node_packagejson.py      # package.json
│   ├── node_lockfiles.py        # package-lock.json, yarn.lock, pnpm-lock.yaml
│   └── ...                      # phase 2 ecosystems (§4.2)
├── normalize.py           # PEP 503 name normalization, npm scope handling
├── report/
│   ├── __init__.py
│   ├── structured.py      # jsonl (primary), json, csv
│   └── table.py           # human-readable
└── errors.py
tests/
├── fixtures/              # synthetic repos: one folder per scenario
└── test_*.py
PLAN.md · README.md · pyproject.toml · requirements-dev.txt
```

### 3.4 Tech stack

- **Python 3.11+**, standard library only — decision 2 (§14) ruled out `PyYAML`, so this
  project ships with **zero third-party runtime dependencies**, same as the sibling project.
- `tomllib` (stdlib since 3.11) parses `pyproject.toml`.
- The catalog is plain **JSON**, loaded with `json.load`.

**The honest cost of that decision:** two target-repo file formats are *real* YAML —
`environment.yml` (conda) and `pnpm-lock.yaml`. Without a YAML library, both are read with a
narrow, purpose-built line parser rather than a general YAML parser:

| File | What the hand-written parser actually handles | What it does NOT handle |
|---|---|---|
| `environment.yml` | Flat `dependencies:` list (`- name=version` / `- name`) and the nested `- pip:` block, both single-level | Anchors, multi-document files, deeply nested channel configs — vanishingly rare in this file in practice |
| `pnpm-lock.yaml` | The top-level `dependencies:` / `devDependencies:` maps (`name: version` or `name: {version: ...}`) that every pnpm lockfile has at depth 1 | The full nested `packages:` resolution graph (transitive tree) — v1 does not attempt transitive pnpm extraction; `--include-transitive` on pnpm reports `unsupported_for_ecosystem` rather than a wrong answer |

This is a real, named trade-off, not an oversight: a full transitive pnpm parse needs either
a real YAML parser or a lot of hand-rolled indentation-tracking code, for a lockfile format
whose own maintainers describe it as an implementation detail. If pnpm transitive coverage
turns out to matter, revisit decision 2 rather than deepening the hand-parser.

Everything else — `json`, `csv`, `re`, `pathlib`, `subprocess` (for git), `dataclasses`,
`argparse`, `logging`, `datetime` — is stdlib.

> **Raven note:** run `raven-init` in this new folder before the first commit — it has no
> `.raven/manifest.json` yet. Since this stays dependency-free, `stack.libraries` only needs
> the dev tools (`pytest`, `ruff`, `mypy`), matching the sibling project.

---

## 4. Manifest coverage

### 4.1 Phase 1 — Python + JavaScript

These two ecosystems cover the overwhelming majority of real AI integration.

| Ecosystem | File | What we read |
|---|---|---|
| Python | `requirements.txt`, `requirements-*.txt`, `requirements/*.txt` | One requirement per line, PEP 508 |
| Python | `constraints.txt` | Same grammar; tagged as constraints, not direct deps |
| Python | `pyproject.toml` | `[project].dependencies` + `[project].optional-dependencies` (PEP 621); `[tool.poetry.dependencies]` + groups; `[tool.pdm]`/`[tool.uv]` dev groups |
| Python | `Pipfile` | `[packages]`, `[dev-packages]` (TOML) |
| Python | `setup.cfg` | `[options] install_requires`, `extras_require` |
| Python | `environment.yml` | conda `dependencies:`, including the nested `pip:` block |
| Node | `package.json` | `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies` |
| Node | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Resolved versions (see §6.2); transitive opt-in |

### 4.2 Additional ecosystems (shipped 2026-08-31, see §14.1)

| Ecosystem | Files | Parser |
|---|---|---|
| Java / Kotlin (Maven) | `pom.xml` | `java_maven.py` |
| Java / Kotlin (Gradle) | `build.gradle`, `build.gradle.kts` | `java_gradle.py` |
| Go | `go.mod` | `go_mod.py` |
| Rust | `Cargo.toml` | `rust_cargo.py` |
| .NET | `*.csproj`/`*.fsproj`/`*.vbproj`, `packages.config`, `Directory.Packages.props` | `dotnet_nuget.py` |
| Ruby | `Gemfile` | `ruby_gemfile.py` |
| PHP | `composer.json` | `php_composer.py` |

Each new ecosystem needed its own version-specifier semantics in
`parsers/base.py::classify_version_spec` — they are not uniform. A bare,
operator-less version means an exact pin in Maven/Gradle/Composer, a
caret range in Cargo (same convention as Poetry), a minimum in NuGet, and
an exact pin again in RubyGems (Bundler). Getting this wrong would
silently violate PLAN.md section 6.1's core promise, so each ecosystem's
convention is documented inline where classified, with a dedicated test.

**Verification caveat (repeated from §14.1):** none of these seven
parsers have been run against a real project — only hand-written
synthetic fixtures, because a machine-wide scan found zero projects in
any of these ecosystems to check them against. Every other parser in
this tool was live-tested and that testing found real bugs; these have
not had that chance yet.

### 4.3 Deliberately excluded from v1

- **`setup.py`** — dependencies are arbitrary Python expressions, not data. Parsing it
  properly means an AST walk that still cannot resolve computed lists, and parsing it
  naively produces silent wrong answers. **Report the file as `unparsed_manifest` in the
  report so its absence from results is visible, never silently skipped.**
- **Vendored trees** — `node_modules/`, `.venv/`, `vendor/`, `site-packages/` (§9).

---

## 5. The AI library catalog

### 5.1 Structure

Stored as `catalog/ai_libraries.json` (decision 2, §14 — JSON, no YAML dependency):

```json
{
  "version": 1,
  "updated": "2026-08-31",
  "libraries": [
    { "name": "openai", "ecosystem": "pypi", "category": "llm_sdk",
      "aliases": ["openai-python"] },
    { "name": "@anthropic-ai/sdk", "ecosystem": "npm", "category": "llm_sdk" }
  ],
  "namespaces": [
    { "pattern": "@langchain/", "ecosystem": "npm", "category": "agent_framework",
      "_comment": "prefix match, npm scope" },
    { "pattern": "langchain-", "ecosystem": "pypi", "category": "agent_framework",
      "_comment": "prefix match, PyPI ecosystem convention" }
  ]
}
```

Two match modes, both explicit, **no free-text regex**:

1. **`libraries`** — exact match on the normalized name (plus declared aliases).
2. **`namespaces`** — explicit prefix match, used only where an ecosystem genuinely
   namespaces a family (`@langchain/*`, `langchain-*`, `@llamaindex/*`, `llama-index-*`).

### 5.2 Categories (descriptive only — see §1.1)

`llm_sdk` · `agent_framework` · `vector_db` · `ml_framework` · `nlp_transformers` ·
`inference_serving` · `observability_evals` · `embeddings_media`

### 5.3 Initial catalog content (illustrative, not exhaustive)

| Category | PyPI | npm |
|---|---|---|
| `llm_sdk` | `openai`, `anthropic`, `cohere`, `mistralai`, `google-generativeai`, `google-genai`, `groq`, `together`, `replicate`, `ai21`, `fireworks-ai`, `huggingface-hub`, `azure-ai-inference` | `openai`, `@anthropic-ai/sdk`, `@google/generative-ai`, `cohere-ai`, `@mistralai/mistralai`, `groq-sdk`, `replicate`, `@huggingface/inference` |
| `agent_framework` | `langchain*`, `langgraph`, `llama-index*`, `haystack-ai`, `semantic-kernel`, `autogen*`, `crewai`, `dspy-ai`, `litellm`, `instructor`, `pydantic-ai`, `smolagents`, `guidance` | `langchain`, `@langchain/*`, `llamaindex`, `ai` (Vercel AI SDK), `@ai-sdk/*` |
| `vector_db` | `pinecone-client`, `weaviate-client`, `qdrant-client`, `chromadb`, `faiss-cpu`, `faiss-gpu`, `pymilvus`, `lancedb`, `pgvector` | `@pinecone-database/pinecone`, `weaviate-ts-client`, `@qdrant/js-client-rest`, `chromadb` |
| `ml_framework` | `torch`, `tensorflow`, `jax`, `keras`, `scikit-learn`, `xgboost`, `lightgbm`, `catboost` | `@tensorflow/tfjs`, `onnxruntime-node` |
| `nlp_transformers` | `transformers`, `sentence-transformers`, `tokenizers`, `datasets`, `accelerate`, `peft`, `trl`, `spacy`, `nltk` | `@xenova/transformers` |
| `inference_serving` | `vllm`, `llama-cpp-python`, `ctransformers`, `onnxruntime`, `ollama` | `ollama` |
| `observability_evals` | `langsmith`, `langfuse`, `mlflow`, `wandb`, `ragas`, `deepeval`, `arize-phoenix` | `langsmith`, `langfuse` |
| `embeddings_media` | `tiktoken`, `diffusers`, `openai-whisper` | `tiktoken`, `gpt-tokenizer` |

### 5.4 The `boto3` problem — a named catalog hazard

`boto3` is the general AWS SDK. A repo using it for S3 has nothing to do with AI; a repo
using it for **Bedrock** does. The package name alone cannot tell them apart.

**Decision: `boto3` is NOT in the catalog.** Including it would generate false evidence at
scale — exactly the failure mode §1.1 exists to prevent. AWS Bedrock usage is detectable
only from client construction in source code, which is the §11.1 phase-2 import scanner's
job, not the manifest scanner's.

The same reasoning excludes: `requests`, `httpx`, `numpy`, `pandas`, `scipy`, `pillow`.
**Document this exclusion list in the catalog file itself, with the reason**, so a future
maintainer doesn't "helpfully" add them back.

> **Amara (Functional):** "Under-reporting is recoverable — someone adds a catalog row.
> Over-reporting burns the reviewer's trust in the whole feed, and they stop reading it.
> Bias toward precision."

---

## 6. The version problem — read this before implementing

### 6.1 A manifest declares a *specifier*, not a version

This is the most likely place for the tool to state something false.

| Declared in file | What it actually is |
|---|---|
| `openai>=1.0,<2` | A range. No single version. |
| `"openai": "^4.20.0"` | A caret range. Resolves to anything `>=4.20.0 <5.0.0`. |
| `openai` | Completely unpinned. |
| `openai==1.30.1` | An actual pin. |
| `openai @ git+https://github.com/...@abc123` | A git URL, not a semver at all. |

**Rule: `dependency_version` carries the raw declared string, verbatim, and never a guess.**
The tool must never resolve, normalize, or "pick the likely version" for a range.

To keep that honest and machine-readable, the record carries two supporting fields
**in addition to** the six specified in §1:

- `version_spec_kind` — `pinned` | `range` | `unpinned` | `url` | `resolved`
- `version_source` — `declared` (from a manifest) | `resolved` (from a lockfile)

> **Yamini (Data):** "Downstream will aggregate `dependency_version` into a chart. If half
> the values are `^4.20.0` and half are `1.30.1`, that chart is meaningless without
> `version_spec_kind` to group by. These fields are not optional decoration."

### 6.2 Lockfiles give real versions

When a lockfile is present alongside a manifest, the same library appears twice with
different `version_source`. Default behaviour: **emit both rows** — the declared intent and
the resolved reality are different facts, and collapsing them loses information.

`--prefer resolved|declared|both` controls this; `both` is the default.

---

## 7. Git provenance

### 7.1 `repo_id`

Resolution order, first hit wins:

1. `--repo-id` if the caller supplies one (authoritative — a caller integrating this into a
   larger system has a better ID than we can derive).
2. `git remote get-url origin`, normalized to `host/org/repo` (strip protocol, credentials,
   and `.git`; lowercase the host). SSH and HTTPS forms must normalize identically.
3. The repository root **directory name**, prefixed `local:` so it is never mistaken for a
   real remote.

### 7.2 `commit_sha` — a real fork in the road

| Option | Meaning | Cost |
|---|---|---|
| **A. Repo HEAD** | One sha for the whole scan: "this is what the repo contained at commit X" | 1 git call |
| **B. Per-file last commit** | `git log -1 --format=%H -- <path>`: "this manifest last changed at commit Y" | N git calls |

**Recommendation: A as `commit_sha`** — the audit question is almost always "what did this
repo look like at commit X", and one anchor keeps every row in a scan mutually consistent.

Option B is genuinely useful for "when did this AI dependency get introduced", so it is
available as `--with-file-commits`, populating an additional `file_last_commit_sha`. It is
opt-in because it costs one subprocess per manifest file.

### 7.3 The dirty-working-tree trap

If the working tree has uncommitted changes, `commit_sha` is **actively misleading** — it
names a commit whose content is not what was scanned.

Handling: always compute `git status --porcelain`; set a report-level `is_dirty` flag and a
per-record `content_matches_commit: false` when the specific manifest file is modified.
Print a visible warning in table output. **Never silently emit a clean-looking sha for
content that isn't in that commit.**

### 7.4 Not a git repo at all

Scanning a plain directory is legitimate (an unpacked tarball, a vendored copy).
`commit_sha` becomes `null`, `repo_id` falls back to `local:<dirname>`, and a
`no_git_context` warning is attached. The scan still runs and still produces useful rows.

---

## 8. Output

### 8.1 Formats

| Format | Use |
|---|---|
| **`jsonl`** (default) | One record per line. The natural shape for this flat schema and for piping into a data store. |
| `json` | Full envelope: scan metadata + records + errors + coverage. |
| `csv` | Spreadsheet / BI import. |
| `table` | Human reading in a terminal. |

### 8.2 Record

```python
@dataclass(frozen=True, slots=True)
class ScanRecord:
    # The six specified fields
    repo_id: str
    file_path: str            # repo-relative, forward slashes on every OS
    dependency_name: str      # normalized (§10)
    dependency_version: str   # raw declared string, verbatim (§6.1)
    commit_sha: str | None    # None when not a git repo (§7.4)
    scan_timestamp: str       # ISO-8601 UTC, identical for every row in one scan

    # Provenance / honesty fields (§6.1, §7.3)
    version_spec_kind: str    # pinned|range|unpinned|url|resolved
    version_source: str       # declared|resolved
    content_matches_commit: bool
    # Descriptive metadata (§1.1 — never a judgment)
    ecosystem: str            # pypi|npm|maven|go|...
    category: str             # llm_sdk|vector_db|...
    dependency_group: str     # main|dev|optional|peer|constraints
    is_direct: bool           # False for transitive lockfile entries
    raw_declaration: str      # the original line/value, for auditability
    match_rule: str           # "exact:openai" | "namespace:@langchain/"
```

`raw_declaration` and `match_rule` exist so any row can be traced back to exactly why it was
emitted — essential when someone challenges a finding.

### 8.3 Coverage reporting — absence must be visible

The JSON envelope always reports **what was looked at**, not only what was found:

```json
"coverage": {
  "manifests_found": 12,
  "manifests_parsed": 11,
  "manifests_unparsed": [{"path": "setup.py", "reason": "setup_py_not_supported"}],
  "ecosystems_seen": ["pypi", "npm"],
  "catalog_version": 1
}
```

A scan that finds zero AI libraries must be distinguishable from a scan that failed to parse
anything. This is the same "absence must be visible, never implied" rule that caught a real
bug in the Extension Searcher project.

### 8.4 Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed — **including when AI libraries were found** (§1.1) |
| `1` | Scan completed but one or more manifests failed to parse |
| `2` | Target path does not exist or is not readable |
| `3` | Bad usage / invalid arguments |

---

## 9. Discovery and ignore rules

Walk from the repo root with `os.scandir`, **pruning ignored directories before descending**
(never walk into them and filter after — that is the difference between a fast scan and one
that reads 40,000 files in `node_modules`).

**Always pruned:** `.git`, `node_modules`, `.venv`, `venv`, `env`, `site-packages`,
`vendor`, `dist`, `build`, `target`, `.tox`, `.mypy_cache`, `.pytest_cache`, `__pycache__`,
`.next`, `.nuxt`.

- `--include-vendored` opts back in (a vendored `package.json` *is* real evidence in some
  audits — the default just shouldn't drown the signal).
- `--respect-gitignore` (default on when in a git repo): use `git check-ignore` in a single
  batched call rather than reimplementing gitignore semantics.
- `--max-depth N` guard against pathological trees.
- Symlinks are **not** followed (`follow_symlinks=False`) — prevents loops and escaping the
  repo root.

---

## 10. Name normalization

Matching the catalog requires normalizing both sides identically, or matches silently fail.

- **PyPI (PEP 503):** lowercase; collapse runs of `-`, `_`, `.` to a single `-`.
  `Sentence_Transformers` → `sentence-transformers`. Non-negotiable — PyPI treats these as
  the same package and real manifests use all the spellings.
- **npm:** lowercase; preserve the `@scope/name` shape exactly.
- **Extras are stripped for matching, kept in `raw_declaration`:** `langchain[all]` matches
  `langchain`.
- **Environment markers stripped:** `openai; python_version >= "3.9"` matches `openai`.

---

## 11. Edge cases register

| # | Case | Handling |
|---|---|---|
| 1 | Comment lines / inline `#` comments in `requirements.txt` | Strip before parsing; `#` inside a URL fragment is not a comment |
| 2 | `-r base.txt` / `-c constraints.txt` includes | Follow, resolve relative to the including file, **cycle-guard with a visited set** |
| 3 | `-e .` / `--editable` local installs | Recognized, recorded, not treated as an AI lib unless the name matches |
| 4 | Git/URL requirements: `openai @ git+https://…` | `version_spec_kind = url`; keep the whole URL in `raw_declaration` |
| 5 | Monorepo: many `package.json` at many depths | All scanned; `file_path` disambiguates; **no dedup across files** — same library in two packages is two facts |
| 6 | Same library in `dependencies` and `devDependencies` | Two rows, distinguished by `dependency_group` |
| 7 | Lockfile transitive deps | Excluded by default; `--include-transitive` sets `is_direct=false` |
| 8 | Poetry's `python = "^3.11"` pseudo-dependency | Excluded — it is a runtime constraint, not a package |
| 9 | Poetry table form: `openai = {version = "^1.0", optional = true}` | Parse the `version` key; record `optional` in `dependency_group` |
| 10 | `environment.yml` nested `pip:` block | Parsed as PyPI ecosystem, not conda |
| 11 | Conda pins use `=` not `==` (`pytorch=2.1`) | Handled by the conda-specific grammar, not the PEP 508 one |
| 12 | Malformed / truncated JSON or TOML | Per-file try/except → `errors[]`, scan continues (never abort the run) |
| 13 | Encoding: BOM, UTF-16, latin-1 manifests | Open UTF-8 with BOM-strip; fall back with `errors="replace"` and warn |
| 14 | Windows path separators in `file_path` | Always emit forward slashes so output is OS-independent |
| 15 | Case-only differences in package names | Normalized per §10 before matching |
| 16 | Empty repo / no manifests at all | Exit `0`, zero records, `coverage.manifests_found = 0` — a valid answer |
| 17 | Very large lockfiles (`package-lock.json` > 50 MB) | Size guard; record `skipped_too_large` rather than blocking |
| 18 | Detached HEAD / zero commits | `commit_sha` from `rev-parse HEAD` if it exists, else `null` + warning |
| 19 | Submodules | Not descended into by default (they are separate repos with separate `repo_id`); `--include-submodules` opts in |
| 20 | Catalog says `namespace: langchain-` and repo has `langchain-that-isnt-real` | Matched — prefix rules are trust-by-design; keep prefixes narrow and reviewed |

### 11.1 The biggest honest limitation

**A manifest scan can be wrong in both directions:**

- **False negative:** a repo that calls `https://api.openai.com` with plain `requests` has
  *real* AI integration and **zero** catalog hits. This tool will report nothing.
- **False positive:** `langchain` sitting in `requirements.txt` unused since a spike a year
  ago is reported as evidence, because it *is* declared.

Neither is a bug — both are inherent to reading manifests rather than code. **The README
must state this plainly**, because a reader who assumes completeness will draw wrong
conclusions from a clean report.

A phase-3 `import`/client-construction scanner (AST-based) would narrow the false-negative
gap. It is explicitly out of scope for v1 and must not be implied as present.

---

## 12. Testing strategy

- **Fixture-driven.** `tests/fixtures/` holds synthetic repo trees — one directory per
  scenario, committed to the repo. **No test reads a real user repo or the network.**
- **Golden-file tests:** fixture repo in → expected JSONL out.
- **A real git fixture** created in `tmp_path` by an actual `git init` + commit, so
  `git_context.py` is tested against real git behaviour, not a mock. Covers: clean tree,
  dirty tree, no-remote, SSH remote, HTTPS remote, detached HEAD, non-repo directory.
- **Malformed corpus:** truncated JSON, invalid TOML, BOM'd UTF-8, a `requirements.txt`
  with every §11 edge case in one file.
- **Catalog integrity test:** no duplicate names within an ecosystem, every entry has a
  valid `category`, every `namespaces` pattern is non-empty and not a bare `-` or `@`.
- **The `boto3` regression test:** assert `boto3`, `requests`, and `numpy` produce **zero**
  records. This locks §5.4 against well-meaning future edits.
- **Normalization property test:** `Sentence_Transformers`, `sentence.transformers`, and
  `sentence-transformers` all match the same catalog entry.
- Target: **≥ 85%** on `parsers/`, `catalog/`, `normalize.py`, `git_context.py`.
- `ruff` clean · `mypy --strict` clean — same bar as the sibling project.

---

## 13. Build phases

| Phase | Deliverable | Exit criterion | Status |
|---|---|---|---|
| **P0** | `models.py`, `errors.py`, `pyproject.toml`, skeleton | `mypy --strict` clean | ✅ Done |
| **P1** | `catalog/` + `normalize.py` | Catalog loads, validates, normalizes; integrity + `boto3` tests pass | ✅ Done — 8 catalog tests including the boto3/requests/numpy exclusion regression |
| **P2** | `git_context.py` | Correct `repo_id`/`commit_sha`/dirty on a real git fixture, and on a non-repo dir | ✅ Done — tested against real git (not mocked); found and fixed a real bug (see below) |
| **P3** | `discovery.py` | Finds every manifest in a fixture monorepo; prunes `node_modules` (verify by timing, not just result) | ✅ Done — found and fixed a second real bug in `--respect-gitignore` (see below) |
| **P4** | Python parsers | All §4.1 Python formats + §11 edge cases 1-4, 8-11 | ✅ Done — requirements/constraints, pyproject (PEP 621/Poetry/PDM/uv), Pipfile, setup.cfg, environment.yml |
| **P5** | Node parsers | `package.json` + the three lockfiles; transitive opt-in works | ✅ Done — package.json, package-lock.json (v1 and v2/v3), yarn.lock, pnpm-lock.yaml |
| **P6** | `report/` + `cli.py` | All four formats; exit codes; coverage block populated | ✅ Done — jsonl/json/csv/table, all four exit codes live-verified |
| **P7** | Tests, README, real-repo dry run | Coverage target met; **run against Extension Searcher and 2-3 real repos** and hand-verify the rows | ✅ Done — 139 tests, 90% coverage (target 85%), ruff and mypy --strict clean. Dry-run against Extension Searcher (0 AI libs, correct) and a positive-control fixture (correct matches, correct boto3/requests exclusion, correct version-specifier verbatim reporting) |

**Shipped: end of P7.** Two real bugs were found via the real-git and real-filesystem testing
P2/P3 called for — exactly as live-host testing surfaced three real bugs in the sibling
Extension Searcher project. Both are now regression-tested:

1. **`git_context.get_modified_paths`** — `_run_git`'s helper called `.strip()` on the whole
   `git status --porcelain` output before splitting into lines. Porcelain's first status
   column can be a literal leading space (`" M file"`), so that strip silently corrupted the
   first line's column alignment. Fixed to `.rstrip()` only; regression test added.
2. **`discovery._gitignored_paths`** — passed `text=True` with a multi-line `input=` string
   to `git check-ignore --stdin`. On Windows, Python's text-mode subprocess pipes translate
   embedded `\n` to `\r\n` on write, appending a stray `\r` to every path in the batch except
   the last — silently breaking exact-match ignore checks for all but the final entry. Fixed
   by passing raw bytes instead of `text=True`; an order-independence regression test added.

---

## 14. Decisions — LOCKED

Accepted via Andie defaults, 2026-08-31.

| # | Decision | Locked | Consequence |
|---|---|---|---|
| 1 | Scan target | ~~One repo per invocation.~~ **REVISED 2026-08-31 (see below): `--system` scans the whole machine.** | `cli.py` takes an optional path argument; `--system` ignores it in favour of `--roots` (default: every fixed drive). |
| 2 | Catalog format | **JSON, not YAML.** Zero new dependencies — matches the sibling project's stdlib-only stance. | `catalog/ai_libraries.yaml` becomes `catalog/ai_libraries.json` throughout §5. `environment.yml`'s conda format still needs a YAML reader for *scanning target repos* (not the catalog) — handled with a narrow, dependency-free line parser (conda files are simple `key: value` / `- item` structures), not a full YAML library. |
| 3 | Consumer | **Stdout / file only.** No network egress, no POST-to-Hub in v1. | Keeps the security surface identical to Extension Searcher: read-only, no outbound calls. |
| 4 | Phase 2 ecosystems | ~~Python + JavaScript only for v1.~~ **REVISED 2026-08-31 (see below): Java/Gradle, Go, Rust, .NET, Ruby, PHP added.** | §4.2 is no longer deferred — updated in place with what shipped and its verification caveat. |

### 14.1 Post-launch revisions

Three decisions above were revisited after the initial build, each at the
owner's explicit request, not found by drift:

**2026-08-31, decision 1 reversed — whole-system scanning.** Added
`--system`: discovers every project on the machine (git-repo root, or
failing that any directory holding a recognized manifest — discovery
does not descend past a found project, so submodules and vendored clones
are not double-counted) and scans each one. A full two-drive scan
completes in ~5-11s. See `system_scan.py` and README.md's "Whole-system
scan" section for the pruning rules and file-budget safety valve.

**2026-08-31, the catalog stopped being a filter.** Not one of the four
original decisions, but load-bearing enough to record here: every
declared dependency is now reported by default (`category=unclassified`,
`is_ai_related=false` for non-AI packages), not only catalog matches. On
the development machine this went from 80 to 5,946 references. `--ai-only`
restores the original filtered behaviour. The neutral framing in §1.1 was
written for AI libraries specifically but reads correctly either way: a
`fastapi` row is evidence of what the code declares, not a verdict on
`fastapi` either.

**2026-08-31, decision 4 reversed — six more ecosystems.** Java (Maven +
Gradle), Go, Rust, .NET, Ruby, and PHP were added, each ecosystem behind
its own parser (`java_maven.py`, `java_gradle.py`, `go_mod.py`,
`rust_cargo.py`, `dotnet_nuget.py`, `ruby_gemfile.py`, `php_composer.py`).
**Important caveat, stated plainly rather than buried:** unlike every
Python/JS parser in this tool, none of these six were verified against a
real project — a machine-wide scan at the time of writing found zero
Java/Go/Rust/.NET/Ruby/PHP projects to check them against. They are
tested only against hand-written synthetic fixtures. Each parser's module
docstring repeats this. If you scan a real project in one of these
ecosystems, treat the first result with extra scrutiny and report
anything that looks wrong — that live-repo check is exactly what found
real bugs in every other parser this tool has (§13's build-phase table).

---

## 15. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Catalog staleness — new AI SDKs ship weekly | **High** | **High** — silent false negatives | Catalog is versioned data with an `updated` date; emit `catalog_version` in every report; schedule a review cadence |
| Over-broad matching burns reviewer trust | Medium | **High** | §5.4 exclusion list + its regression test; narrow, reviewed namespace prefixes only |
| Specifier reported as if it were a version | Medium | Medium | `version_spec_kind` is mandatory, not optional (§6.1) |
| Dirty tree produces a misleading `commit_sha` | Medium | Medium | `is_dirty` + per-record `content_matches_commit` (§7.3) |
| Neutral framing erodes into a policy gate | Medium | **High** | No fail-on-found flag, no severity field, ever (§1.1) |
| Scan is slow on large monorepos | Low | Medium | Prune-before-descend; size guards; batched `git check-ignore` |
| Someone reads a clean report as "no AI here" | **High** | **High** | §11.1 stated in README, `--help`, and the JSON envelope's coverage block |

---

## 16. Handoff

Andie plans; Andie does not implement. On approval of this plan and the §14 decisions:

- `/andie-jr` — build phase by phase, or
- `raven-plan` → `raven-test` (test-first) → implementation.

**Before the first commit:** run `raven-init` in this folder to create
`.raven/manifest.json` (this is a new project — it has no manifest yet), set
`stack.language = ["python"]`, and add any approved dependency from §3.4 to
`stack.libraries`.

---
*Planned by Andie v6.4 📘 Deep · Triad: Amara (OSS Compliance) · Andres (Static Analysis)
· Yamini (Provenance Data) · Lior (Devil's Advocate, AppSec)*
