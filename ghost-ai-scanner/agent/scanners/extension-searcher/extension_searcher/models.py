"""Normalized record types and enums. Zero logic — dataclasses only.

See PLAN.md section 8 for the schema this module implements, and section
15 for the four locked scope decisions (cross-OS, dual output, Safari/IE
in scope, current-user only) that shaped these shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Engine(StrEnum):
    """The extension-storage format a browser uses."""

    CHROMIUM = "chromium"
    GECKO = "gecko"
    WEBKIT = "webkit"
    TRIDENT = "trident"


class ExtensionState(StrEnum):
    """Tri-state enabled/disabled/unknown, used internally by parsers.

    Records expose this as ``enabled: bool | None`` (see ExtensionRecord) —
    this enum is the parser-side intermediate before that conversion.
    """

    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class InstallOrigin(StrEnum):
    """Where an extension came from, per PLAN.md section 8."""

    WEBSTORE = "webstore"
    AMO = "amo"
    MAC_APP_STORE = "mac_app_store"
    SIDELOADED = "sideloaded"
    POLICY = "policy"
    BUILTIN = "builtin"
    UNPACKED = "unpacked"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    """How complete a record's data is.

    PARTIAL is the expected, correct value for every Safari and Internet
    Explorer record (PLAN.md section 5.3) — it reflects a platform limit,
    not a parsing failure.
    """

    FULL = "full"
    PARTIAL = "partial"
    STATE_ONLY = "state_only"


@dataclass(frozen=True, slots=True)
class ExtensionRecord:
    """One extension, in one profile, in one browser. The single output shape
    every parser (chromium/gecko/webkit/trident) normalizes into."""

    # Identity
    extension_id: str
    name: str
    version: str
    description: str | None

    # Where it lives
    browser: str
    browser_channel: str | None
    engine: Engine
    profile_dir: str
    profile_name: str | None
    install_path: str

    # State
    enabled: bool | None
    disabled_reason: str | None
    state_source: str

    # Origin / trust
    install_origin: InstallOrigin
    update_url: str | None
    signed_state: str | None
    is_builtin: bool
    is_unpacked: bool

    # Security surface
    manifest_version: int | None
    permissions: tuple[str, ...] = field(default_factory=tuple)
    host_permissions: tuple[str, ...] = field(default_factory=tuple)
    content_script_matches: tuple[str, ...] = field(default_factory=tuple)
    has_background_worker: bool | None = None

    # Timeline
    install_time: str | None = None
    update_time: str | None = None

    # Provenance
    source_files: tuple[str, ...] = field(default_factory=tuple)
    confidence: Confidence = Confidence.FULL
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ProfileHit:
    """One discovered profile directory within a browser's user-data root."""

    profile_dir: str
    profile_name: str | None
    path: str
    engine: Engine


@dataclass(frozen=True, slots=True)
class BrowserHit:
    """One browser's discovery result — found or not, and where it looked.

    ``roots_checked`` is always populated, even when ``found`` is False —
    per PLAN.md section 14, absence must be visible, never implied.
    """

    name: str
    engine: Engine
    found: bool
    roots_checked: tuple[str, ...]
    profiles: tuple[ProfileHit, ...] = field(default_factory=tuple)
    unverified: bool = False


@dataclass(frozen=True, slots=True)
class ScanError:
    """One recoverable failure surfaced in the report's ``errors`` list."""

    path: str
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Aggregate counts for the report envelope."""

    browsers_found: int
    profiles: int
    extensions: int
    unique_extensions: int
    disabled: int
    sideloaded: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The full report envelope — PLAN.md section 8."""

    host: str
    os_name: str
    started_at: str
    finished_at: str
    tool_version: str
    duration_ms: int
    browsers: tuple[BrowserHit, ...]
    extensions: tuple[ExtensionRecord, ...]
    errors: tuple[ScanError, ...]
    summary: ScanSummary
    unverified_paths: tuple[str, ...] = field(default_factory=tuple)
