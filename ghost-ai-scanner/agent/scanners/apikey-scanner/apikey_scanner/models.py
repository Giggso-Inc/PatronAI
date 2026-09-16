"""Normalized record types. Dataclasses only, zero logic.

HARD INVARIANT (PLAN.md section 1.1): no dataclass in this module has a
`value`, `match`, `snippet`, `preview`, or `line_text` field, and none may
ever be added. A finding is identified by *where* a secret is (repo, file,
line, column, length) and *what kind* it looks like -- never by the bytes
of the secret itself. Reviewers: a pull request that adds a field capable
of holding secret material to any class below is the single most dangerous
change this project can receive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Confidence(StrEnum):
    """Structural certainty that a match is the shape it claims to be.

    This is NOT severity. A `high` confidence generic-looking token found
    in a test fixture is not "worse" than a `low` one in production code --
    that judgment is left to the consumer (PLAN.md section 1.2).
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Detector(StrEnum):
    REGEX = "regex"
    ENTROPY = "entropy"


class ProvenanceState(StrEnum):
    """What git could tell us about the line the match landed on.

    PLAN.md section 7.3: never fabricate a HEAD sha for a line git could
    not attribute. A null commit_sha that means "unknown" beats a
    plausible wrong answer.
    """

    COMMITTED = "committed"
    UNCOMMITTED_CHANGE = "uncommitted_change"
    UNTRACKED = "untracked"
    NOT_A_REPO = "not_a_repo"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    ALLOWLISTED = "allowlisted"


@dataclass(frozen=True, slots=True)
class PatternSpec:
    """One compiled catalog entry. Loaded from catalog/patterns.json."""

    id: str
    name: str
    provider: str
    kind: str
    confidence: Confidence
    capture_group: int
    requires_identifier_proximity: bool
    validate: str | None
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Detection:
    """One match on one line, before git provenance is attached.

    Carries the match's *shape* only: where it starts, how long it is, and
    which pattern fired. `matched_text` deliberately does not exist here --
    the engine reduces a `re.Match` to this dataclass in the same
    expression that produces it (PLAN.md section 1.1.2), so the secret
    never survives past the line it was found on.
    """

    pattern_id: str
    provider: str
    confidence: Confidence
    detector: Detector
    line_number: int
    column_start: int
    match_length: int
    entropy_bits: float | None = None
    secret_fingerprint: str | None = None
    """Set only when --track-rotation is enabled (PLAN.md section 6.2). A
    salted HMAC computed in detect/engine.py at the instant the candidate
    is in scope -- never re-derived from anything stored."""


@dataclass(frozen=True, slots=True)
class GitBlameInfo:
    provenance_state: ProvenanceState
    commit_sha: str | None
    author_name: str | None
    author_email: str | None
    author_timestamp: str | None  # ISO-8601 UTC


@dataclass(frozen=True, slots=True)
class Finding:
    """One reportable occurrence. This is the record PLAN.md section 1
    specifies -- every field here is detection metadata, never the secret.
    """

    finding_id: str
    repo_id: str
    repo_path: str
    file_path: str
    line_number: int
    column_start: int
    match_length: int
    matched_pattern_type: str
    pattern_id: str
    provider: str
    confidence: Confidence
    detector: Detector
    entropy_bits: float | None
    commit_sha: str | None
    author_name: str | None
    author_email: str | None
    author_timestamp: str | None
    provenance_state: ProvenanceState
    is_git_tracked: bool
    is_gitignored: bool
    in_test_path: bool
    scan_timestamp: str
    secret_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class RepoContext:
    repo_id: str
    repo_path: str
    is_git_repo: bool
    head_sha: str | None
    branch: str | None
    remote_url: str | None


@dataclass(slots=True)
class ScanSummary:
    repos_scanned: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    findings_total: int = 0
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)
