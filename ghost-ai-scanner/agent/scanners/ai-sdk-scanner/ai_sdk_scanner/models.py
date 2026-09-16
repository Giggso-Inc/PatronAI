"""Normalized record types and enums. Zero logic — dataclasses only.

See PLAN.md section 8 for the schema this module implements, and section
14 for the locked scope decisions (one repo per run, JSON catalog, no
network, Python+JS v1) that shaped these shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Ecosystem(StrEnum):
    """Package ecosystem a dependency was declared in.

    Gradle (build.gradle/build.gradle.kts) uses the same group:artifact:
    version coordinate system as Maven's pom.xml, so it shares MAVEN
    rather than getting its own value — the coordinate namespace and
    catalog entries are identical either way.
    """

    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"
    COMPOSER = "composer"


class VersionSpecKind(StrEnum):
    """What kind of thing `dependency_version` actually holds.

    PLAN.md section 6.1: a manifest usually declares a *specifier*, not a
    version. This field exists so downstream consumers never mistake
    "^4.20.0" for a concrete version.
    """

    PINNED = "pinned"
    RANGE = "range"
    UNPINNED = "unpinned"
    URL = "url"
    RESOLVED = "resolved"


class VersionSource(StrEnum):
    """Whether a version came from a manifest's declared intent, or from a
    lockfile's resolved reality (PLAN.md section 6.2)."""

    DECLARED = "declared"
    RESOLVED = "resolved"


class DependencyGroup(StrEnum):
    """Which dependency group a reference belongs to."""

    MAIN = "main"
    DEV = "dev"
    OPTIONAL = "optional"
    PEER = "peer"
    CONSTRAINTS = "constraints"


class Category(StrEnum):
    """Descriptive category of a dependency — never a risk judgment.

    PLAN.md section 1.1: this says what kind of library it is, never how
    concerning it is. There is deliberately no severity/risk enum anywhere
    in this module.

    UNCLASSIFIED is the honest value for the majority of dependencies: the
    catalog identifies AI/ML libraries specifically, so everything else is
    "not in the AI catalog", NOT "categorised as non-AI". Pair it with
    `ScanRecord.is_ai_related` to filter.
    """

    UNCLASSIFIED = "unclassified"
    LLM_SDK = "llm_sdk"
    AGENT_FRAMEWORK = "agent_framework"
    VECTOR_DB = "vector_db"
    ML_FRAMEWORK = "ml_framework"
    NLP_TRANSFORMERS = "nlp_transformers"
    INFERENCE_SERVING = "inference_serving"
    OBSERVABILITY_EVALS = "observability_evals"
    EMBEDDINGS_MEDIA = "embeddings_media"


@dataclass(frozen=True, slots=True)
class DependencyRef:
    """One dependency line, as a parser found it — before catalog matching.

    This is the contract every parser in `parsers/` returns (PLAN.md
    section 3.3). Catalog matching turns a subset of these into
    `ScanRecord`s; most `DependencyRef`s are not AI libraries and are
    simply discarded after matching.

    Every field after `file_path` is optional enrichment: a parser
    populates what its format actually provides and leaves the rest at
    its default. A `None` here means "this format does not express that",
    not "we failed to read it".
    """

    name: str  # raw, not yet normalized
    raw_declaration: str  # the original line/value, verbatim
    version_spec: str  # raw declared version string, verbatim
    version_spec_kind: VersionSpecKind
    version_source: VersionSource
    ecosystem: Ecosystem
    dependency_group: DependencyGroup
    is_direct: bool
    file_path: str  # repo-relative, forward slashes

    # --- Declaration detail (parsed out, previously discarded) ---
    extras: tuple[str, ...] = field(default_factory=tuple)
    environment_marker: str | None = None
    version_constraints: tuple[str, ...] = field(default_factory=tuple)
    line_number: int | None = None
    is_optional: bool = False

    # --- Source of the package, where the manifest declares one ---
    declared_index_url: str | None = None
    vcs_url: str | None = None
    vcs_ref: str | None = None
    local_path: str | None = None

    # --- Lockfile-only supply-chain metadata ---
    resolved_url: str | None = None
    integrity: str | None = None
    declared_license: str | None = None
    has_install_script: bool | None = None


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """One AI/ML library reference. PLAN.md section 8.2 — the output shape.

    A `None` in any optional field means "the source format does not
    express this", never "we failed to read it" — the distinction matters
    when reading results, and is why nothing here defaults to a
    placeholder string.
    """

    # === The six originally-specified fields ===
    repo_id: str
    file_path: str
    dependency_name: str
    dependency_version: str
    commit_sha: str | None
    scan_timestamp: str

    # === Provenance / honesty (sections 6.1, 7.3) ===
    version_spec_kind: VersionSpecKind
    version_source: VersionSource
    content_matches_commit: bool

    # === Descriptive classification (section 1.1 — never a judgment) ===
    ecosystem: Ecosystem
    category: Category
    dependency_group: DependencyGroup
    is_direct: bool
    raw_declaration: str
    # Empty for dependencies not in the AI catalog; when set, states exactly
    # which catalog rule matched, so any AI classification is traceable.
    match_rule: str
    # True only when the AI catalog matched. Every dependency is collected
    # regardless; this is the flag to filter on, not `category`.
    is_ai_related: bool = False

    # === Name resolution ===
    # `normalized_name` is the key catalog matching actually used (PEP 503
    # for PyPI, lowercased for npm). Group and dedupe on this, not on
    # `dependency_name`, which preserves the manifest's own spelling.
    normalized_name: str = ""
    extras: tuple[str, ...] = field(default_factory=tuple)

    # === Version detail ===
    # `version_constraints` decomposes ">=1.0,<2" into (">=1.0", "<2").
    version_constraints: tuple[str, ...] = field(default_factory=tuple)
    environment_marker: str | None = None

    # === Precise location ===
    # `line_number` is best-effort: exact for line-oriented formats
    # (requirements.txt), located by key search for structured ones
    # (TOML/JSON), None when not determinable.
    line_number: int | None = None
    manifest_kind: str = ""

    # === Where the package would come from ===
    declared_index_url: str | None = None
    vcs_url: str | None = None
    vcs_ref: str | None = None
    local_path: str | None = None
    is_optional: bool = False

    # === Lockfile supply-chain metadata (resolved installs only) ===
    resolved_url: str | None = None
    integrity: str | None = None
    declared_license: str | None = None
    has_install_script: bool | None = None

    # === Manifest file fingerprint ===
    manifest_sha256: str | None = None
    manifest_mtime: str | None = None
    manifest_size: int | None = None

    # === Git provenance ===
    git_branch: str | None = None
    git_remote_url: str | None = None
    commit_date: str | None = None
    commit_author: str | None = None
    # Opt-in (--with-file-commits): absence is the normal case, not a gap.
    file_last_commit_sha: str | None = None
    file_last_commit_date: str | None = None
    file_last_commit_author: str | None = None

    # === Project context (populated in --system mode) ===
    project_root: str | None = None
    project_name: str | None = None
    project_discovered_by: str | None = None


@dataclass(frozen=True, slots=True)
class UnparsedManifest:
    """A manifest file that was found but could not be parsed."""

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class ManifestError:
    """One recoverable failure surfaced in the report's `errors` list."""

    path: str
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class CoverageInfo:
    """What was looked at, not only what was found (PLAN.md section 8.3)."""

    manifests_found: int
    manifests_parsed: int
    manifests_unparsed: tuple[UnparsedManifest, ...]
    ecosystems_seen: tuple[str, ...]
    catalog_version: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The full report envelope for ONE project — PLAN.md section 8.3."""

    repo_id: str
    commit_sha: str | None
    is_dirty: bool
    scan_timestamp: str
    tool_version: str
    duration_ms: int
    records: tuple[ScanRecord, ...]
    errors: tuple[ManifestError, ...]
    coverage: CoverageInfo
    warnings: tuple[str, ...] = field(default_factory=tuple)
    project_root: str | None = None  # absolute path; set in system-scan mode
    # Carried explicitly rather than inferred from `commit_sha is not None`:
    # a freshly `git init`-ed repo with no commits yet has no commit_sha but
    # IS a git repo, and inferring got that case wrong.
    is_git_repo: bool = False
    git_branch: str | None = None
    git_remote_url: str | None = None
    commit_date: str | None = None
    commit_author: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredProject:
    """One project root found during a system-wide walk.

    `discovered_by` records WHY this directory was treated as a project —
    a git repo root, or a bare manifest with no enclosing repo. That
    distinction matters when reading results: a `manifest_only` project
    has no commit_sha to anchor its findings to.
    """

    path: str
    discovered_by: str  # "git_repo" | "manifest_only"


@dataclass(frozen=True, slots=True)
class SystemScanSummary:
    """Aggregate counts across every project in a system scan."""

    projects_found: int
    projects_with_ai_refs: int
    total_references: int
    unique_dependencies: int
    git_projects: int
    manifest_only_projects: int
    # AI-specific subtotals. Kept alongside the totals rather than
    # replacing them: "how many dependencies are there" and "how many are
    # AI" are both real questions and the ratio matters.
    ai_references: int = 0
    unique_ai_dependencies: int = 0
    projects_with_any_refs: int = 0


@dataclass(frozen=True, slots=True)
class SystemScanReport:
    """Envelope for a whole-system scan: many projects, one report.

    `roots_scanned` and `dirs_pruned` are always populated so a small
    result set is distinguishable from a scan that never looked — the
    same "absence must be visible" rule as PLAN.md section 8.3.
    """

    host: str
    scan_timestamp: str
    tool_version: str
    duration_ms: int
    roots_scanned: tuple[str, ...]
    dirs_pruned: int
    dirs_visited: int
    access_denied_count: int
    projects: tuple[ScanReport, ...]
    summary: SystemScanSummary
    warnings: tuple[str, ...] = field(default_factory=tuple)
