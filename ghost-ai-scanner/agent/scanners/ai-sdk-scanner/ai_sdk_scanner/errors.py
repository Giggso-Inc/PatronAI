"""Typed exception hierarchy.

Every parser failure is caught individually and converted into a
`ManifestError` (see models.py) rather than propagating — one bad manifest
must never abort the whole scan (PLAN.md section 11, edge case 12).
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for all errors raised within this tool."""

    kind: str = "unknown"


class ManifestParseError(ScannerError):
    """Raised when a manifest file cannot be parsed."""

    kind = "manifest_parse_failed"


class CatalogError(ScannerError):
    """Raised when the AI-library catalog itself is invalid.

    Unlike ManifestParseError, this is fatal — a broken catalog means every
    match result is untrustworthy, so the scan must not proceed silently.
    """

    kind = "catalog_invalid"


class GitContextError(ScannerError):
    """Raised for unrecoverable git-command failures (not 'not a repo')."""

    kind = "git_context_failed"


class TargetNotFoundError(ScannerError):
    """Raised when the scan target path does not exist or is not readable."""

    kind = "target_not_found"
