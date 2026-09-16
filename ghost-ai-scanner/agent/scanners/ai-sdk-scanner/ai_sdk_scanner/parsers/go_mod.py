"""go.mod — Go modules. Verified only against synthetic fixtures (no real
Go project exists on the development machine at the time of writing).

`require` entries only. `replace` and `exclude` directives are recognized
by the block/directive detector but not emitted as dependencies — a
`replace` redirects where a dependency resolves from (often to a fork or
a local path) rather than declaring a new one, and `exclude` removes a
version rather than adding a reference. Modelling those precisely would
need to merge them against the `require` list; skipped for v1 rather than
guessed at.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.parsers.base import classify_version_spec

logger = logging.getLogger(__name__)

_REQUIRE_BLOCK_START_RE = re.compile(r"^require\s*\($")
_REQUIRE_SINGLE_RE = re.compile(r"^require\s+(\S+)\s+(\S+)")
_BLOCK_ENTRY_RE = re.compile(r"^(\S+)\s+(\S+)")


def _strip_comment(line: str) -> tuple[str, bool]:
    """Strip a trailing `//` comment; report whether it said "indirect"."""
    is_indirect = False
    if "//" in line:
        code, _, comment = line.partition("//")
        is_indirect = "indirect" in comment
        line = code
    return line.strip(), is_indirect


def parse(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return []

    refs: list[DependencyRef] = []
    in_require_block = False

    for line_number, raw_line in enumerate(lines, start=1):
        stripped, is_indirect = _strip_comment(raw_line)
        if not stripped:
            continue

        if in_require_block:
            if stripped == ")":
                in_require_block = False
                continue
            entry_match = _BLOCK_ENTRY_RE.match(stripped)
            if entry_match:
                refs.append(
                    _make_ref(
                        entry_match.group(1), entry_match.group(2),
                        file_path=file_path, is_direct=not is_indirect,
                        raw=raw_line.strip(), line_number=line_number,
                    )
                )
            continue

        if _REQUIRE_BLOCK_START_RE.match(stripped):
            in_require_block = True
            continue

        single_match = _REQUIRE_SINGLE_RE.match(stripped)
        if single_match:
            refs.append(
                _make_ref(
                    single_match.group(1), single_match.group(2),
                    file_path=file_path, is_direct=not is_indirect,
                    raw=raw_line.strip(), line_number=line_number,
                )
            )
            continue

        # module / go / toolchain / replace / exclude / retract -- not a
        # dependency declaration (see module docstring for replace/exclude).

    return refs


def _make_ref(
    module_path: str, version: str, *, file_path: str, is_direct: bool, raw: str,
    line_number: int,
) -> DependencyRef:
    return DependencyRef(
        name=module_path,
        raw_declaration=raw,
        version_spec=version,
        version_spec_kind=classify_version_spec(version, Ecosystem.GO),
        version_source=VersionSource.DECLARED,
        ecosystem=Ecosystem.GO,
        dependency_group=DependencyGroup.MAIN,
        is_direct=is_direct,
        file_path=file_path,
        line_number=line_number,
    )
