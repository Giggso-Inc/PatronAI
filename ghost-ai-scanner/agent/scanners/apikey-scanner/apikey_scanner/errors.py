"""Exception types. Every raise site passes file_path/line_number only --
never the matched text (PLAN.md section 1.1.4)."""

from __future__ import annotations


class ApiKeyScannerError(Exception):
    """Base class for all errors raised by this tool."""


class CatalogError(ApiKeyScannerError):
    """The pattern catalog is malformed or internally inconsistent."""


class ConfigError(ApiKeyScannerError):
    """The scanner configuration file or CLI arguments are invalid."""


class StoreError(ApiKeyScannerError):
    """The findings database could not be read or written."""
