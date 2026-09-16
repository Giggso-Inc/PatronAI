# Six-Ecosystem Expansion — Detailed Documentation

**Feature:** Java/Kotlin (Maven + Gradle), Go, Rust, .NET, Ruby, and PHP
dependency parsing, added on top of the existing Python and JavaScript
support.
**Status:** shipped, committed as `bbb5ccc` ("Add Java, Go, Rust, .NET,
Ruby, and PHP ecosystems").
**Verification status:** ⚠️ **synthetic fixtures only** — see
[Verification caveat](#verification-caveat) before trusting a real scan.

This document covers two things the README only summarizes: the exact
**output structure** each new ecosystem produces, and precisely **where
every field's data comes from**. For the feature's design rationale and
decision history, see [PLAN.md](../PLAN.md) sections 4.2 and 14.1.

---

## 1. What was added

| Ecosystem | Manifest file(s) | Parser module | Coordinate system |
|---|---|---|---|
| Java / Kotlin (Maven) | `pom.xml` | [`parsers/java_maven.py`](../ai_sdk_scanner/parsers/java_maven.py) | `groupId:artifactId` |
| Java / Kotlin (Gradle) | `build.gradle`, `build.gradle.kts` | [`parsers/java_gradle.py`](../ai_sdk_scanner/parsers/java_gradle.py) | `group:artifact` (same coordinate system as Maven — see §2) |
| Go | `go.mod` | [`parsers/go_mod.py`](../ai_sdk_scanner/parsers/go_mod.py) | module import path, e.g. `github.com/org/repo` |
| Rust | `Cargo.toml` | [`parsers/rust_cargo.py`](../ai_sdk_scanner/parsers/rust_cargo.py) | crate name |
| .NET | `*.csproj`/`*.fsproj`/`*.vbproj`, `packages.config`, `Directory.Packages.props` | [`parsers/dotnet_nuget.py`](../ai_sdk_scanner/parsers/dotnet_nuget.py) | NuGet package ID |
| Ruby | `Gemfile` | [`parsers/ruby_gemfile.py`](../ai_sdk_scanner/parsers/ruby_gemfile.py) | gem name |
| PHP | `composer.json` | [`parsers/php_composer.py`](../ai_sdk_scanner/parsers/php_composer.py) | `vendor/package` |

Each manifest is discovered by [`discovery.py`](../ai_sdk_scanner/discovery.py)
(`MANIFEST_FILENAMES` / `_DOTNET_PROJECT_EXTENSIONS` / `_classify()`),
dispatched to its parser by [`pipeline.py`](../ai_sdk_scanner/pipeline.py)'s
`_parse_manifest()`, matched against the AI catalog, and emitted as a
`ScanRecord` — the exact same pipeline every Python/JS manifest goes
through. Nothing about the output shape is ecosystem-specific; only the
*parsing* is.

## 2. Why Gradle shares `Ecosystem.MAVEN`

`build.gradle`/`build.gradle.kts` files declare dependencies using the
same `group:artifact:version` coordinate namespace as `pom.xml` — a
Gradle-declared `com.openai:openai-java` and a Maven-declared
`com.openai:openai-java` are the *same* package on Maven Central, so
they must normalize and catalog-match identically. Rather than
duplicating every Maven catalog entry under a separate `GRADLE`
ecosystem, `Ecosystem.MAVEN` is reused for both (`models.py:14-30`), and
[`normalize.py`](../ai_sdk_scanner/normalize.py) deliberately has **no**
`normalize_maven_name()` — the catalog loader's generic
`name.strip().lower()` fallback handles the combined `"group:artifact"`
string for both file formats.

## 3. Output structure

Every dependency — from any of the nine ecosystems — becomes one
`ScanRecord` ([`models.py:135-221`](../ai_sdk_scanner/models.py)), a flat
43-field record. `None`/empty always means *"this format does not
express that"*, never *"we failed to read it"*.

### 3.1 Fields and their source, grouped by concern

| Field | Source | Notes for the new ecosystems |
|---|---|---|
| `repo_id` | derived from the repo's git remote, or `--repo-id` override | unaffected by ecosystem |
| `file_path` | manifest's path relative to repo root, forward-slashed | e.g. `services/api/pom.xml` |
| `dependency_name` | raw name exactly as declared in the manifest | Maven/Gradle: `"groupId:artifactId"`; Go: full module path; Cargo/NuGet/RubyGems: bare name; Composer: `vendor/package` |
| `dependency_version` | raw version string, **verbatim** | never resolved or guessed — see §4 |
| `commit_sha` | `git rev-parse HEAD` at scan time | project-level, not per-manifest |
| `scan_timestamp` | wall-clock time the scan ran | — |
| `normalized_name` | ecosystem-specific normalizer (§5) | the catalog-matching key; group/dedupe on this, not `dependency_name` |
| `extras` | not populated by any of the 6 new parsers | Python-only concept (PEP 508 extras); always `()` here |
| `version_spec_kind` | `parsers/base.py:classify_version_spec()` | **semantics differ per ecosystem** — see §4, the single most important thing this feature got right |
| `version_source` | always `DECLARED` for these 6 | none of them are lockfile formats; `RESOLVED` only applies to npm/PyPI lockfiles |
| `version_constraints` | not populated by any of the 6 new parsers | PyPI-specific (`split_version_constraints()`); always `()` here |
| `environment_marker` | not populated | PEP 508-specific; always `None` here |
| `line_number` | parser-computed, see §6 | exact for line-oriented formats (Go, Gradle, Ruby); best-effort key search for structured ones (Maven/NuGet XML, Cargo TOML, Composer JSON) |
| `manifest_kind` | discovery's `_classify()` string | `java_maven`, `java_gradle`, `go_mod`, `rust_cargo`, `dotnet_project`, `dotnet_packages_config`, `dotnet_central_packages`, `ruby_gemfile`, `php_composer` |
| `ecosystem` | fixed per parser | `maven`, `go`, `cargo`, `nuget`, `rubygems`, `composer` |
| `category` | AI catalog match, or `unclassified` | see §7 |
| `is_ai_related` | `True` iff a catalog rule matched | the field to filter on |
| `dependency_group` | parser-derived from scope/config/section (§8) | `main` / `dev` / `optional` / `constraints` |
| `is_direct` | `True` for all 6, except Go's `// indirect` | Go is the only one of the 9 ecosystems that distinguishes direct vs. transitive *within the manifest itself* |
| `is_optional` | Maven `<optional>`, Gradle `compileOnly*`, Cargo `optional = true` | `False` elsewhere |
| `declared_index_url` | not populated by any of the 6 new parsers | none of these formats declare an alternate package index in the manifest itself |
| `vcs_url` / `vcs_ref` | Cargo `git =` table, Ruby `git:`/`github:` | `None` for Maven/Gradle/Go/NuGet/Composer (their manifest formats don't express a VCS source per-dependency) |
| `local_path` | Cargo `path =`, Ruby `path:` | `None` elsewhere |
| `resolved_url` / `integrity` / `declared_license` / `has_install_script` | not populated | lockfile-only fields (npm's `package-lock.json`/`yarn.lock`); none of the 6 new ecosystems' *manifest* formats (as opposed to their lockfiles, which aren't parsed) express these |
| `manifest_sha256` / `manifest_mtime` / `manifest_size` | computed by `pipeline.py:_fingerprint()` from the file itself | identical mechanism for every ecosystem |
| `git_branch`, `git_remote_url`, `commit_date`, `commit_author` | `git_context.py`, one batched `git log`/`git branch` call per project | project-level, not per-manifest |
| `file_last_commit_sha/_date/_author` | `git_context.py:get_file_last_commit_info()`, opt-in via `--with-file-commits` | per-manifest-file |
| `project_root`, `project_name`, `project_discovered_by` | populated only in `--system` mode | — |
| `raw_declaration` | the literal source text the parser matched | see §9 for the exact string shape per ecosystem |
| `match_rule` | which catalog entry/namespace matched, or `""` | traces every AI classification back to one rule |

### 3.2 Output formats

The same `ScanRecord` set renders three ways
([`report/structured.py`](../ai_sdk_scanner/report/structured.py)):

- **JSONL** (default) — one JSON object per line, every key present even
  when `null` (no key omission).
- **JSON** — a full envelope: `{"scan": {...}, "records": [...],
  "errors": [...], "coverage": {...}, "warnings": [...]}`.
- **CSV** — the same fields in a fixed column order (identity → name
  resolution → version detail → location → classification → package
  source → supply chain → fingerprint → git provenance → project context
  → auditability); tuple fields (`extras`, `version_constraints`) are
  joined with `;`.

None of the three formats differ by ecosystem — a Go row and a PyPI row
have identical shape, just different values.

## 4. Version-specifier classification — the part that had to be right per ecosystem

`dependency_version` is always the **raw declared string, verbatim**.
`version_spec_kind` is the only signal for what *kind* of value that is
— and its rules are genuinely different per ecosystem. Getting one
backwards would have silently violated the tool's core promise (PLAN.md
§6.1: never guess a version). Implemented in
[`parsers/base.py:classify_version_spec()`](../ai_sdk_scanner/parsers/base.py):

| Ecosystem | A bare version with no operator (e.g. `"1.2.3"`) means | Range syntax | Explicit exact-pin syntax |
|---|---|---|---|
| Go | always `PINNED` — go.mod has no range operator at all, every entry (including pseudo-versions like `v0.0.0-20210101000000-abcdef123456`) is one concrete version | n/a | n/a |
| Maven / Gradle | `PINNED` (no implicit caret) | `[1.0,2.0)` bracket syntax, or Gradle's `1.+`/`+` | — |
| Cargo | `RANGE` — **implicit caret**, same convention as Python's Poetry | any bare version (see left) | `=1.2.3` prefix |
| NuGet | `RANGE` — a bare version means "**minimum**", not exact; a real gotcha if you assume otherwise | bracket/range syntax (`[1.0,2.0)`) | `[1.2.3]` exact bracket form |
| RubyGems | `PINNED` — Bundler/RubyGems convention, **opposite of Cargo/Poetry** | `~>` (pessimistic operator), or any `<`/`>` comparison | — |
| Composer | `PINNED` — no implicit caret, same as Maven | `^`/`~`/comparison operators | — |

`${property}` placeholders in Maven (`${jackson.version}`) and Cargo's
`workspace = true` (no inline version) both classify as `UNPINNED`
rather than being resolved — both require cross-file resolution (parent
POM inheritance, workspace root) that this parser deliberately does not
attempt (single-manifest scope, PLAN.md §7.2's precedent).

## 5. Name normalization per ecosystem

Catalog matching requires normalizing both the manifest name and the
catalog entry the same way, or matches silently fail. Each new
ecosystem got its own function in
[`normalize.py`](../ai_sdk_scanner/normalize.py):

| Ecosystem | Function | Rule |
|---|---|---|
| Go | `normalize_go_name` | lowercase (a deliberate simplification — Go import paths are technically case-sensitive, but collision risk is negligible for known SDK paths) |
| Cargo | `normalize_cargo_name` | PEP-503-style folding: lowercase, `-`/`_`/`.` collapsed to `-` (documented crates.io behavior — `-` and `_` are equivalent in a crate name) |
| NuGet | `normalize_nuget_name` | lowercase (NuGet package IDs are case-insensitive on nuget.org) |
| RubyGems | `normalize_rubygems_name` | lowercase |
| Composer | `normalize_composer_name` | lowercase (`vendor/package` form preserved) |
| Maven/Gradle | *(none — generic fallback)* | catalog loader's plain `name.strip().lower()` on the combined `"group:artifact"` string |

## 6. Line-number precision per ecosystem

`line_number` is exact for line-oriented formats and best-effort
(first-match key search) for structured ones:

| Ecosystem | Format | Precision |
|---|---|---|
| Go | line-oriented text | exact |
| Gradle | line-oriented text | exact |
| Ruby (Gemfile) | line-oriented text | exact |
| Maven (`pom.xml`) | XML | best-effort — searches for the literal `<artifactId>x</artifactId>` string |
| .NET (XML forms) | XML | best-effort — case-insensitive substring search for the package name |
| Cargo (`Cargo.toml`) | TOML | best-effort — shared `find_line_number()` helper, key/list-item search |
| Composer (`composer.json`) | JSON | best-effort — same shared helper |

## 7. AI/ML catalog coverage for the 6 new ecosystems

29 exact-match entries plus 4 namespace rules were added to
[`catalog/ai_libraries.json`](../ai_sdk_scanner/catalog/ai_libraries.json):

| Ecosystem | Exact-match entries (examples) | Namespace rules |
|---|---|---|
| Maven | `com.openai:openai-java`, `dev.langchain4j:langchain4j`, `io.qdrant:client`, `io.weaviate:client`, `org.deeplearning4j:deeplearning4j-core`, `ai.djl:api`, `org.tensorflow:tensorflow-core-platform` | `dev.langchain4j:*` → agent_framework, `ai.djl.*` → embeddings_media |
| Go | `github.com/sashabaranov/go-openai`, `github.com/pinecone-io/go-pinecone`, `github.com/qdrant/go-client`, `github.com/milvus-io/milvus-sdk-go` | `github.com/tmc/langchaingo*`, `github.com/anthropics/*` |
| Cargo | `async-openai`, `qdrant-client`, `tokenizers`, `candle-core`, `ort` | — |
| NuGet | `OpenAI`, `Azure.AI.OpenAI`, `Microsoft.SemanticKernel`, `Microsoft.ML`, `TensorFlow.NET` | — |
| RubyGems | `ruby-openai`, `langchainrb`, `tiktoken_ruby` | — |
| Composer | `openai-php/client`, `theodo-group/llphant` | — |

A dependency **not** in this list is still emitted as a normal
`ScanRecord` with `category=UNCLASSIFIED` and `is_ai_related=False` — it
is never dropped (README "Every dependency is reported by default").

## 8. `dependency_group` mapping per ecosystem

| Ecosystem | `main` | `dev` | `optional` | `constraints` |
|---|---|---|---|---|
| Maven | no `<scope>`, or `compile`/`runtime` | `<scope>test</scope>` | `<scope>provided\|system</scope>`, or `<optional>true</optional>` | `<dependencyManagement>` block |
| Gradle | `implementation`, `api`, `runtimeOnly`, `classpath`, etc. | `test*`, `androidtest*`, `annotationProcessor`, `kapt*`, `ksp` | `compileOnly`, `compileOnlyApi` (also sets `is_optional=True`) | — |
| Go | all `require` entries | — | — | — |
| Cargo | `[dependencies]` | `[dev-dependencies]`, `[build-dependencies]` | any entry with `optional = true` | — |
| .NET | `<PackageReference>` | `PrivateAssets="All"` or `"analyzers"` | — | `Directory.Packages.props` → `CONSTRAINTS` (same precedent as pip's `constraints.txt`) |
| .NET (`packages.config`) | default | `developmentDependency="true"` | — | — |
| Ruby | top-level `gem` calls | inside `group :test`/`:development 	do...end` | — | — |
| PHP | `require` | `require-dev` | — | — |

## 9. `raw_declaration` shape per ecosystem

`raw_declaration` is the literal text the parser matched, kept for
auditability (trace any row back to exactly why it was emitted):

- **Maven**: `"groupId:artifactId:version"` (or without version if none declared)
- **Gradle**: the stripped source line, e.g. `implementation 'com.openai:openai-java:0.5.0'`
- **Go**: the stripped source line, e.g. `github.com/sashabaranov/go-openai v1.20.0`
- **Cargo**: `"name = {python repr of the TOML value}"`, e.g. `async-openai = '0.20.0'`
- **.NET**: `Include="name" Version="version"`
- **Ruby**: the stripped source line, e.g. `gem 'ruby-openai', '6.0'`
- **Composer**: `"name": "version_spec"` JSON-style

## 10. What each parser deliberately does NOT read

Named limitations, not bugs — each is documented in its module's
docstring:

| Ecosystem | Not parsed | Why |
|---|---|---|
| Maven | `<profiles>` | profile activation (JDK version, OS, `-P` flag) isn't evaluated here; declaring conditional deps as unconditional would overclaim |
| Maven | `${property}` resolution | requires parent-POM inheritance this parser doesn't fetch — reported verbatim, classified `UNPINNED` |
| Gradle | version-catalog refs (`libs.some.lib`), string interpolation (`"$group:$artifact:$version"`), anything built by a function call or loop | Gradle build files are code, not data — only the common literal-declaration shapes are regular enough to extract |
| Go | `replace` / `exclude` directives | these redirect/remove a resolution rather than declare a new dependency; modelling them precisely needs merging against `require`, skipped for v1 |
| Cargo | `[workspace.dependencies]` resolution for `workspace = true` entries | no cross-file resolution — `version_spec` is left empty (`UNPINNED`) rather than guessed |
| .NET | — (all three formats fully parsed) | — |
| Ruby | anything built dynamically (loop, conditional, interpolated string) | same class of problem as Gradle — a Gemfile is Ruby code |
| PHP | platform pseudo-packages (`php`, `ext-*`, `lib-*`, `composer-plugin-api`, `composer-runtime-api`) | these declare a runtime requirement, not a Packagist package (same reasoning as excluding Poetry's `python = "^3.11"` key) |

None of the 6 new ecosystems' **lockfiles** are parsed (`Gemfile.lock`,
`composer.lock`, `go.sum`, `Cargo.lock`, `packages.lock.json`) — only
their manifests. This mirrors the tool's existing Python behavior more
than its JS behavior: JS lockfiles (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`) *are* parsed for supply-chain fields, but that wasn't
extended to the 6 new ecosystems in this pass.

## 11. Verification caveat

**None of the six new parsers have been run against a real project.**
Before writing any of this code, a recursive filesystem scan across both
local drives was run to check what actually exists on the development
machine — it found zero Go, Rust, .NET, Ruby, or PHP projects, and the
one Java hit was JDK installer metadata, not a project. The user was
asked how to proceed and explicitly chose to build these parsers anyway,
verified only by hand-written synthetic fixtures (`tests/test_java_maven.py`,
`test_java_gradle.py`, `test_go_mod.py`, `test_rust_cargo.py`,
`test_dotnet_nuget.py`, `test_ruby_gemfile.py`, `test_php_composer.py`,
`test_new_ecosystems_pipeline.py`).

Every bug this tool has actually shipped with — the `git status`
leading-space bug, the Windows subprocess newline-corruption bug, the
`langchain` catalog gap — was found by running it against **real** code.
Python and JavaScript had that; these six ecosystems have not. Treat a
first real scan in any of them as worth a closer look than usual, and
report anything that looks wrong.

This caveat is also recorded in [PLAN.md §14.1](../PLAN.md) and the
[README](../README.md#what-it-reads) ecosystem table.

## 12. End-to-end example

Given a repo containing:

```
pom.xml           → com.openai:openai-java 0.5.0
go.mod             → github.com/sashabaranov/go-openai v1.20.0
Cargo.toml         → async-openai = "0.20.0"  (+ serde = "1.0")
app.csproj         → OpenAI 2.0.0
Gemfile            → gem 'ruby-openai', '6.0'  (+ gem 'rails', '7.0')
composer.json      → "openai-php/client": "^0.10.0"  (+ "monolog/monolog": "^3.0")
```

`python -m ai_sdk_scanner <repo> --format table` reports **6 manifests
found, 6 parsed, 0 errors**, ecosystems seen = `{maven, go, cargo,
nuget, rubygems, composer}`, 6 AI-related rows (one per ecosystem's
OpenAI-family SDK) and 3 unclassified rows (`serde`, `rails`,
`monolog/monolog`) sorted after them. `php` itself never appears as a
row (platform package exclusion, §10). This exact fixture is what
`tests/test_new_ecosystems_pipeline.py` asserts against.

## 13. Related documents

- [PLAN.md](../PLAN.md) §4.2 (parser specs), §14.1 (decision history and
  the verification-caveat rationale)
- [README.md](../README.md) — user-facing usage and the ecosystem table
- Module docstrings in each of the 7 new parser files — the most
  detailed, closest-to-the-code version of the limitations in §10
