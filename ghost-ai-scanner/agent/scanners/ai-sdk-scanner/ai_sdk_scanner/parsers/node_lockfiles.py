"""package-lock.json, yarn.lock, pnpm-lock.yaml. PLAN.md sections 4.1, 6.2.

Lockfiles supply RESOLVED versions (version_source=resolved) alongside the
manifest's DECLARED intent — both are kept as separate rows by design
(PLAN.md section 6.2): a specifier and its resolution are different facts.

Direct-vs-transitive detection quality varies by format on purpose (see
each parser's docstring) rather than being silently overclaimed as uniform.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from ai_sdk_scanner.models import (
    DependencyGroup,
    DependencyRef,
    Ecosystem,
    VersionSource,
    VersionSpecKind,
)

logger = logging.getLogger(__name__)


def _resolved_ref(
    name: str,
    version: str,
    *,
    group: DependencyGroup,
    is_direct: bool,
    file_path: str,
    raw: str,
    resolved_url: str | None = None,
    integrity: str | None = None,
    declared_license: str | None = None,
    has_install_script: bool | None = None,
    is_optional: bool = False,
) -> DependencyRef:
    """Build a resolved (lockfile-sourced) ref.

    The optional keyword fields are lockfile-only supply-chain metadata:
    where the artifact actually came from (`resolved_url`), its content
    hash (`integrity`), its declared license, and whether installing it
    runs an arbitrary script (`has_install_script`). None of these exist
    in a plain manifest, which is why they are only populated here.
    """
    return DependencyRef(
        name=name,
        raw_declaration=raw,
        version_spec=version,
        version_spec_kind=VersionSpecKind.RESOLVED,
        version_source=VersionSource.RESOLVED,
        ecosystem=Ecosystem.NPM,
        dependency_group=group,
        is_direct=is_direct,
        file_path=file_path,
        resolved_url=resolved_url,
        integrity=integrity,
        declared_license=declared_license,
        has_install_script=has_install_script,
        is_optional=is_optional,
    )


# ---------------------------------------------------------------------------
# package-lock.json (npm)
# ---------------------------------------------------------------------------

def parse_package_lock_json(
    path: Path, *, file_path: str, include_transitive: bool
) -> list[DependencyRef]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        logger.warning("Could not parse %s", path, exc_info=True)
        return []
    if not isinstance(data, dict):
        return []

    if "packages" in data:
        return _parse_lockfile_v2plus(
            data["packages"], file_path=file_path, include_transitive=include_transitive
        )
    if "dependencies" in data:
        return _parse_lockfile_v1(
            data["dependencies"], file_path=file_path, depth=0,
            include_transitive=include_transitive,
        )
    return []


def _parse_lockfile_v2plus(
    packages: dict[str, Any], *, file_path: str, include_transitive: bool
) -> list[DependencyRef]:
    """npm lockfileVersion 2/3: a flat map keyed by node_modules path.

    Direct-vs-transitive is approximated by path depth: exactly one
    "node_modules/" segment means the package sits at the top of the tree.
    This is a heuristic, not a guarantee — npm's flat install can hoist a
    transitive dependency to the top level too. It is documented as such
    rather than presented as exact.
    """
    refs: list[DependencyRef] = []
    for key, entry in packages.items():
        if key == "" or not isinstance(entry, dict):
            continue  # "" is the root project itself
        if "node_modules/" not in key:
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        depth = key.count("node_modules/")
        is_direct = depth == 1
        if not is_direct and not include_transitive:
            continue
        version = entry.get("version")
        if not isinstance(version, str):
            continue
        group = DependencyGroup.DEV if entry.get("dev") else DependencyGroup.MAIN
        refs.append(
            _resolved_ref(
                name, version, group=group, is_direct=is_direct, file_path=file_path, raw=key,
                resolved_url=_str_or_none(entry.get("resolved")),
                integrity=_str_or_none(entry.get("integrity")),
                declared_license=_str_or_none(entry.get("license")),
                has_install_script=entry.get("hasInstallScript") is True,
                is_optional=entry.get("optional") is True,
            )
        )
    return refs


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _parse_lockfile_v1(
    tree: dict[str, Any], *, file_path: str, depth: int, include_transitive: bool
) -> list[DependencyRef]:
    """npm lockfileVersion 1: a nested tree. Depth 0 is direct; anything
    nested under a package's own "dependencies" is transitive."""
    refs: list[DependencyRef] = []
    is_direct = depth == 0
    if is_direct or include_transitive:
        for name, entry in tree.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str):
                group = DependencyGroup.DEV if entry.get("dev") else DependencyGroup.MAIN
                refs.append(
                    _resolved_ref(
                        name, version, group=group, is_direct=is_direct,
                        file_path=file_path, raw=f"{name}@{version}",
                        resolved_url=_str_or_none(entry.get("resolved")),
                        integrity=_str_or_none(entry.get("integrity")),
                        is_optional=entry.get("optional") is True,
                    )
                )
    if include_transitive:
        for entry in tree.values():
            if isinstance(entry, dict) and isinstance(entry.get("dependencies"), dict):
                refs.extend(
                    _parse_lockfile_v1(
                        entry["dependencies"], file_path=file_path,
                        depth=depth + 1, include_transitive=include_transitive,
                    )
                )
    return refs


# ---------------------------------------------------------------------------
# yarn.lock — a custom format, not YAML and not JSON
# ---------------------------------------------------------------------------

_YARN_HEADER_SPEC_RE = re.compile(r'"?([^"@,]+(?:@[^"@,]+)?)@[^",]+"?')
_YARN_VERSION_RE = re.compile(r'^\s*version\s+"?([^"\s]+)"?')
_YARN_RESOLVED_RE = re.compile(r'^\s*resolved\s+"?([^"\s]+)"?')
_YARN_INTEGRITY_RE = re.compile(r'^\s*integrity\s+"?([^"\s]+)"?')


def parse_yarn_lock(path: Path, *, file_path: str, include_transitive: bool) -> list[DependencyRef]:
    """Every entry in yarn.lock is flat, with no direct/transitive marker
    of its own — that distinction lives only in package.json. Because of
    that, every entry here is emitted with is_direct=False, gated fully
    behind --include-transitive; use node_packagejson.py for direct deps
    and this parser purely to attach resolved versions when transitive
    coverage is requested.
    """
    if not include_transitive:
        return []

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return []

    refs: list[DependencyRef] = []
    # `resolved` and `integrity` appear AFTER the `version` line within a
    # block, so each block is buffered and only emitted once the next
    # header (or EOF) proves it complete. Emitting on the version line, as
    # an earlier version did, silently dropped both fields.
    names: list[str] = []
    header_raw = ""
    version: str | None = None
    resolved_url: str | None = None
    integrity: str | None = None

    def flush() -> None:
        nonlocal names, version, resolved_url, integrity
        if names and version:
            for name in names:
                refs.append(
                    _resolved_ref(
                        name, version, group=DependencyGroup.MAIN, is_direct=False,
                        file_path=file_path, raw=header_raw,
                        resolved_url=resolved_url, integrity=integrity,
                    )
                )
        names, version, resolved_url, integrity = [], None, None, None

    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            flush()
            header_raw = line.rstrip().rstrip(":")
            names = _extract_yarn_names(header_raw)
            continue
        if version is None:
            version_match = _YARN_VERSION_RE.match(line)
            if version_match:
                version = version_match.group(1)
                continue
        if resolved_url is None:
            resolved_match = _YARN_RESOLVED_RE.match(line)
            if resolved_match:
                resolved_url = resolved_match.group(1)
                continue
        if integrity is None:
            integrity_match = _YARN_INTEGRITY_RE.match(line)
            if integrity_match:
                integrity = integrity_match.group(1)

    flush()
    return refs


def _extract_yarn_names(header: str) -> list[str]:
    """A yarn.lock header can list several specs for the same resolved
    version: `"openai@^4.20.0", "openai@^4.21.0":`. Extract each unique
    package name, correctly handling scoped packages (`@scope/name@^1.0`)."""
    names: set[str] = set()
    for spec in header.split(","):
        spec = spec.strip().strip('"')
        if spec.startswith("@"):
            # Scoped: split on the SECOND '@' (the one before the range).
            parts = spec.split("@")
            if len(parts) >= 3:
                names.add("@" + parts[1])
        else:
            name = spec.split("@")[0]
            if name:
                names.add(name)
    return sorted(names)


# ---------------------------------------------------------------------------
# pnpm-lock.yaml — real YAML, hand-parsed narrowly (PLAN.md section 3.4)
# ---------------------------------------------------------------------------

def parse_pnpm_lock(path: Path, *, file_path: str, include_transitive: bool) -> list[DependencyRef]:
    """Reads only the top-level `dependencies:`/`devDependencies:` maps —
    the direct, resolved-version dependencies every pnpm lockfile has at
    depth 1. Does NOT attempt the nested `packages:` transitive graph
    (see PLAN.md section 3.4); `include_transitive` is accepted for
    interface consistency but has no effect here — it is a no-op limited
    by design, not silently ignored.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return []

    refs: list[DependencyRef] = []
    section: DependencyGroup | None = None
    section_indent: int | None = None
    # A package name declared as a bare `name:` key (block style) defers
    # its version to a nested `version:` line — tracked here until found.
    pending_name: str | None = None
    pending_name_indent: int | None = None

    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0 and stripped.rstrip(":") in ("dependencies", "devDependencies"):
            section = DependencyGroup.DEV if stripped.startswith("dev") else DependencyGroup.MAIN
            section_indent = indent
            pending_name = None
            continue
        if indent == 0:
            section = None
            pending_name = None
            continue
        if section is None or section_indent is None or indent <= section_indent:
            continue

        # A nested `version:` line under a pending bare-name package.
        if (
            pending_name is not None
            and pending_name_indent is not None
            and indent > pending_name_indent
            and stripped.startswith("version:")
        ):
            version = stripped[len("version:"):].strip().strip("'\"")
            refs.append(
                _resolved_ref(
                    pending_name, version, group=section, is_direct=True,
                    file_path=file_path, raw=f"{pending_name}: {version}",
                )
            )
            pending_name = None
            continue

        if indent != section_indent + 2:
            continue  # deeper nesting we don't otherwise care about

        pending_name = None
        name, version = _parse_pnpm_dep_line(stripped)
        if name and version:
            refs.append(
                _resolved_ref(
                    name, version, group=section, is_direct=True,
                    file_path=file_path, raw=stripped,
                )
            )
        elif name:
            # Bare `name:` with no inline value — version is on a nested line.
            pending_name = name
            pending_name_indent = indent

    return refs


def _parse_pnpm_dep_line(stripped: str) -> tuple[str, str]:
    """`name: 1.2.3`, `'@scope/name': 1.2.3`, or `name: {version: 1.2.3, ...}`
    -> (name, version). YAML quotes scoped package names (they contain a
    `/`), so both the key and any quoted version must be unquoted here."""
    if ":" not in stripped:
        return "", ""
    name, _, rest = stripped.partition(":")
    name = name.strip().strip("'\"")
    rest = rest.strip()
    if rest.startswith("{"):
        version_match = re.search(r"version:\s*([^\s,}]+)", rest)
        version = version_match.group(1) if version_match else ""
        return name, version.strip("'\"")
    return name, rest.strip("'\"")
