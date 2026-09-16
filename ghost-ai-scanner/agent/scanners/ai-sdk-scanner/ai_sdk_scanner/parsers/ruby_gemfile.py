"""Gemfile — RubyGems/Bundler. Verified only against synthetic fixtures
(no real Ruby project exists on the development machine at the time of
writing).

A Gemfile is Ruby code, not data — same class of problem as Gradle build
files (see `java_gradle.py`). The `gem 'name', 'constraint', key: value`
call shape is regular enough to extract line-by-line; anything built
dynamically (a loop, a conditional, an interpolated string) is silently
skipped, the same named limitation as Gradle's version catalogs.

`group :test do ... end` blocks are tracked with a simple stack — nested
blocks are rare in real Gemfiles, and any group containing `:test` or
`:development` maps the whole block's gems to DependencyGroup.DEV.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.parsers.base import classify_version_spec

logger = logging.getLogger(__name__)

_GEM_RE = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"](.*)$""")
_LEADING_VERSION_RE = re.compile(r"""^\s*,\s*['"]([^'"]+)['"]""")
_GIT_RE = re.compile(r"""\bgit:\s*['"]([^'"]+)['"]""")
_GITHUB_RE = re.compile(r"""\bgithub:\s*['"]([^'"]+)['"]""")
_PATH_RE = re.compile(r"""\bpath:\s*['"]([^'"]+)['"]""")
_REF_KEY_RE = re.compile(r"""\b(?:branch|tag|ref):\s*['"]([^'"]+)['"]""")
_GROUP_LINE_RE = re.compile(r"""^\s*group\s+(.+?)\s+do\b""")
_GROUP_SYMBOL_RE = re.compile(r""":(\w+)""")
_DEV_GROUP_NAMES = frozenset({"test", "development"})


def parse(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return []

    refs: list[DependencyRef] = []
    group_stack: list[bool] = []  # each entry: is this an active dev-ish group?

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        group_match = _GROUP_LINE_RE.match(stripped)
        if group_match:
            symbols = {s.lower() for s in _GROUP_SYMBOL_RE.findall(group_match.group(1))}
            group_stack.append(bool(symbols & _DEV_GROUP_NAMES))
            continue
        if stripped == "end" and group_stack:
            group_stack.pop()
            continue

        gem_match = _GEM_RE.match(raw_line)
        if not gem_match:
            continue

        name, rest = gem_match.groups()
        version_match = _LEADING_VERSION_RE.match(rest)
        version = version_match.group(1) if version_match else ""

        vcs_url: str | None = None
        vcs_ref: str | None = None
        local_path: str | None = None

        git_match = _GIT_RE.search(rest)
        github_match = _GITHUB_RE.search(rest)
        if git_match:
            vcs_url = git_match.group(1)
        elif github_match:
            vcs_url = f"https://github.com/{github_match.group(1)}"
        path_match = _PATH_RE.search(rest)
        if path_match:
            local_path = path_match.group(1)
        ref_match = _REF_KEY_RE.search(rest)
        if ref_match:
            vcs_ref = ref_match.group(1)

        in_dev_group = any(group_stack)
        version_spec = vcs_url if (vcs_url and not version) else version

        refs.append(
            DependencyRef(
                name=name,
                raw_declaration=stripped,
                version_spec=version_spec,
                version_spec_kind=classify_version_spec(version_spec, Ecosystem.RUBYGEMS),
                version_source=VersionSource.DECLARED,
                ecosystem=Ecosystem.RUBYGEMS,
                dependency_group=DependencyGroup.DEV if in_dev_group else DependencyGroup.MAIN,
                is_direct=True,
                file_path=file_path,
                line_number=line_number,
                vcs_url=vcs_url,
                vcs_ref=vcs_ref,
                local_path=local_path,
            )
        )

    return refs
