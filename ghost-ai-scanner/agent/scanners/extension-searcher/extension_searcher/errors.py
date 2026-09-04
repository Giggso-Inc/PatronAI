"""Typed exception hierarchy.

Every parser failure is caught individually and converted into a `ScanError`
(see models.py) rather than propagating. These exception types exist to carry
a stable `kind` string into that conversion — never to crash the run.
"""

from __future__ import annotations


class ExtensionSearcherError(Exception):
    """Base class for all errors raised within this tool."""

    kind: str = "unknown"


class ProfileDiscoveryError(ExtensionSearcherError):
    """Raised when a browser's profile list cannot be resolved."""

    kind = "profile_discovery_failed"


class ManifestParseError(ExtensionSearcherError):
    """Raised when an extension manifest or state file cannot be parsed."""

    kind = "json_decode"


class AccessDeniedError(ExtensionSearcherError):
    """Raised when a file or registry key exists but cannot be read.

    Covers both `PermissionError` on the filesystem and macOS TCC denials
    (e.g. missing Full Disk Access for `~/Library/Safari`).
    """

    kind = "access_denied"


class UnsupportedPlatformError(ExtensionSearcherError):
    """Raised when a parser is invoked on an OS it does not support."""

    kind = "unsupported_platform"


class ExternalToolError(ExtensionSearcherError):
    """Raised when an external tool (e.g. `pluginkit`) is missing or fails."""

    kind = "external_tool_failed"
