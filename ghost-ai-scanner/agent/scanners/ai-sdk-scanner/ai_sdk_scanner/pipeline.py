"""Orchestration: discover manifests, parse them, match against the
catalog, attach git provenance. PLAN.md section 3.1 pipeline."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path

from ai_sdk_scanner.catalog.loader import Catalog, normalize_for
from ai_sdk_scanner.discovery import DiscoveredManifest, discover_manifests
from ai_sdk_scanner.errors import ManifestParseError
from ai_sdk_scanner.git_context import (
    GitContext,
    build_git_context,
    get_file_last_commit_info,
)
from ai_sdk_scanner.models import (
    Category,
    CoverageInfo,
    DependencyRef,
    ManifestError,
    ScanRecord,
    ScanReport,
    UnparsedManifest,
)
from ai_sdk_scanner.parsers import (
    dotnet_nuget,
    go_mod,
    java_gradle,
    java_maven,
    node_lockfiles,
    node_packagejson,
    php_composer,
    python_misc,
    python_pyproject,
    python_requirements,
    ruby_gemfile,
    rust_cargo,
)

logger = logging.getLogger(__name__)

_UNPARSED_KINDS = {"python_setup_py_unparsed"}
_FINGERPRINT_MAX_BYTES = 25 * 1024 * 1024


def _fingerprint(path: Path) -> tuple[str | None, str | None, int | None]:
    """(sha256, mtime_iso_utc, size_bytes) for a manifest file.

    Lets a consumer tell "this row is from the same manifest content I saw
    last scan" from "the manifest changed", independently of git — which
    matters for uncommitted edits. Returns Nones rather than raising if
    the file cannot be read.
    """
    try:
        stat = path.stat()
        if stat.st_size > _FINGERPRINT_MAX_BYTES:
            return None, _iso_utc(stat.st_mtime), stat.st_size
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return digest, _iso_utc(stat.st_mtime), stat.st_size
    except OSError:
        return None, None, None


def _iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _parse_manifest(
    manifest: DiscoveredManifest, *, include_transitive: bool
) -> list[DependencyRef]:
    kind = manifest.kind
    path = manifest.abs_path
    fp = manifest.file_path

    if kind in ("python_requirements", "python_constraints"):
        return python_requirements.parse(path, file_path=fp, kind=kind)
    if kind == "python_pyproject":
        return python_pyproject.parse(path, file_path=fp)
    if kind == "python_pipfile":
        return python_misc.parse_pipfile(path, file_path=fp)
    if kind == "python_setup_cfg":
        return python_misc.parse_setup_cfg(path, file_path=fp)
    if kind == "python_environment_yml":
        return python_misc.parse_environment_yml(path, file_path=fp)
    if kind == "node_package_json":
        return node_packagejson.parse(path, file_path=fp)
    if kind == "node_lock_npm":
        return node_lockfiles.parse_package_lock_json(
            path, file_path=fp, include_transitive=include_transitive
        )
    if kind == "node_lock_yarn":
        return node_lockfiles.parse_yarn_lock(
            path, file_path=fp, include_transitive=include_transitive
        )
    if kind == "node_lock_pnpm":
        return node_lockfiles.parse_pnpm_lock(
            path, file_path=fp, include_transitive=include_transitive
        )
    if kind == "java_maven":
        return java_maven.parse(path, file_path=fp)
    if kind == "java_gradle":
        return java_gradle.parse(path, file_path=fp)
    if kind == "go_mod":
        return go_mod.parse(path, file_path=fp)
    if kind == "rust_cargo":
        return rust_cargo.parse(path, file_path=fp)
    if kind == "dotnet_project":
        return dotnet_nuget.parse_project_file(path, file_path=fp)
    if kind == "dotnet_packages_config":
        return dotnet_nuget.parse_packages_config(path, file_path=fp)
    if kind == "dotnet_central_packages":
        return dotnet_nuget.parse_central_package_versions(path, file_path=fp)
    if kind == "ruby_gemfile":
        return ruby_gemfile.parse(path, file_path=fp)
    if kind == "php_composer":
        return php_composer.parse(path, file_path=fp)

    return []


def run_scan(
    repo_root: Path,
    catalog: Catalog,
    *,
    explicit_repo_id: str | None = None,
    include_vendored: bool = False,
    respect_gitignore: bool = True,
    include_transitive: bool = False,
    with_file_commits: bool = False,
    max_depth: int | None = None,
    max_files: int | None = None,
    ai_only: bool = False,
) -> ScanReport:
    scan_timestamp = datetime.now(UTC).isoformat()

    git_ctx: GitContext = build_git_context(repo_root, explicit_repo_id=explicit_repo_id)

    manifests, walk_truncated = discover_manifests(
        repo_root,
        include_vendored=include_vendored,
        respect_gitignore=respect_gitignore,
        is_git_repo=git_ctx.is_git_repo,
        max_depth=max_depth,
        max_files=max_files,
    )

    records: list[ScanRecord] = []
    errors: list[ManifestError] = []
    unparsed: list[UnparsedManifest] = []
    ecosystems_seen: set[str] = set()
    parsed_count = 0

    for manifest in manifests:
        if manifest.kind in _UNPARSED_KINDS:
            unparsed.append(UnparsedManifest(path=manifest.file_path, reason=manifest.kind))
            continue

        try:
            refs = _parse_manifest(manifest, include_transitive=include_transitive)
        except ManifestParseError as exc:
            errors.append(ManifestError(path=manifest.file_path, kind=exc.kind, detail=str(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 - one bad manifest must never abort the scan
            logger.warning("Unexpected parser failure on %s", manifest.file_path, exc_info=True)
            errors.append(
                ManifestError(path=manifest.file_path, kind="parser_exception", detail=str(exc))
            )
            continue

        parsed_count += 1

        # Fingerprint the manifest once, not once per matching dependency.
        fingerprint = _fingerprint(manifest.abs_path)

        for ref in refs:
            ecosystems_seen.add(ref.ecosystem.value)
            match = catalog.match(ref.name, ref.ecosystem)

            # EVERY dependency is emitted. The AI catalog classifies rather
            # than filters: an unmatched package is recorded with
            # category=unclassified and is_ai_related=False. `ai_only`
            # restores the older AI-only behaviour for callers that want it.
            if ai_only and match is None:
                continue

            content_matches_commit = manifest.file_path not in git_ctx.modified_paths

            records.append(
                ScanRecord(
                    repo_id=git_ctx.repo_id,
                    file_path=ref.file_path,
                    dependency_name=ref.name,
                    dependency_version=ref.version_spec,
                    commit_sha=git_ctx.commit_sha,
                    scan_timestamp=scan_timestamp,
                    version_spec_kind=ref.version_spec_kind,
                    version_source=ref.version_source,
                    content_matches_commit=content_matches_commit,
                    ecosystem=ref.ecosystem,
                    category=match.category if match else Category.UNCLASSIFIED,
                    dependency_group=ref.dependency_group,
                    is_direct=ref.is_direct,
                    raw_declaration=ref.raw_declaration,
                    match_rule=match.match_rule if match else "",
                    is_ai_related=match is not None,
                    # Name resolution: the key the catalog actually matched on.
                    normalized_name=normalize_for(ref.name, ref.ecosystem),
                    extras=ref.extras,
                    # Version detail
                    version_constraints=ref.version_constraints,
                    environment_marker=ref.environment_marker,
                    # Location
                    line_number=ref.line_number,
                    manifest_kind=manifest.kind,
                    # Package source
                    declared_index_url=ref.declared_index_url,
                    vcs_url=ref.vcs_url,
                    vcs_ref=ref.vcs_ref,
                    local_path=ref.local_path,
                    is_optional=ref.is_optional,
                    # Lockfile supply-chain metadata
                    resolved_url=ref.resolved_url,
                    integrity=ref.integrity,
                    declared_license=ref.declared_license,
                    has_install_script=ref.has_install_script,
                    # Manifest fingerprint
                    manifest_sha256=fingerprint[0],
                    manifest_mtime=fingerprint[1],
                    manifest_size=fingerprint[2],
                    # Git provenance
                    git_branch=git_ctx.branch,
                    git_remote_url=git_ctx.remote_url,
                    commit_date=git_ctx.commit_date,
                    commit_author=git_ctx.commit_author,
                )
            )

    if with_file_commits and git_ctx.is_git_repo:
        # Opt-in enrichment (PLAN.md section 7.2, option B) — one git call
        # per unique manifest file that actually produced a record, cached
        # so a file with many matching dependencies costs one call, not N.
        from dataclasses import replace

        file_commit_cache: dict[str, tuple[str | None, str | None, str | None]] = {}
        for i, record in enumerate(records):
            if record.file_path not in file_commit_cache:
                file_commit_cache[record.file_path] = get_file_last_commit_info(
                    repo_root, record.file_path
                )
            sha, date, author = file_commit_cache[record.file_path]
            records[i] = replace(
                record,
                file_last_commit_sha=sha,
                file_last_commit_date=date,
                file_last_commit_author=author,
            )

    coverage = CoverageInfo(
        manifests_found=len(manifests),
        manifests_parsed=parsed_count,
        manifests_unparsed=tuple(unparsed),
        ecosystems_seen=tuple(sorted(ecosystems_seen)),
        catalog_version=catalog.version,
    )

    return ScanReport(
        repo_id=git_ctx.repo_id,
        commit_sha=git_ctx.commit_sha,
        is_dirty=git_ctx.is_dirty,
        scan_timestamp=scan_timestamp,
        tool_version=_tool_version(),
        duration_ms=0,  # filled in by cli.py, which owns timing start/stop
        records=tuple(records),
        errors=tuple(errors),
        coverage=coverage,
        warnings=(
            (*git_ctx.warnings, "walk_truncated") if walk_truncated else git_ctx.warnings
        ),
        is_git_repo=git_ctx.is_git_repo,
        git_branch=git_ctx.branch,
        git_remote_url=git_ctx.remote_url,
        commit_date=git_ctx.commit_date,
        commit_author=git_ctx.commit_author,
    )


def _tool_version() -> str:
    from ai_sdk_scanner import __version__

    return __version__
