"""Per-repo and whole-scan orchestration. PLAN.md section 3.1, 10.

Ties together: file walk -> line scan -> git blame (batched per file,
post-filter only, section 7.2) -> stable finding_id (section 6.1) -> Finding.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from apikey_scanner.blame import blame_lines
from apikey_scanner.catalog.loader import Catalog
from apikey_scanner.config import ScannerConfig
from apikey_scanner.detect.engine import scan_text
from apikey_scanner.git_context import build_repo_context, is_path_gitignored, is_path_tracked
from apikey_scanner.identity import build_anchor, compute_finding_id
from apikey_scanner.models import Finding, GitBlameInfo, ProvenanceState, RepoContext, ScanSummary
from apikey_scanner.secret_salt import hash_author
from apikey_scanner.walk import walk_repo_files

_TEST_PATH_RE = re.compile(
    r"(?i)(?:(^|/)(tests?|spec|specs|__tests__|__mocks__)(/|$)|(^|/)[^/]*[_.-]tests?\.[a-z0-9]+$)"
)


def _looks_like_test_path(repo_relative_posix: str) -> bool:
    return bool(_TEST_PATH_RE.search(repo_relative_posix))


def scan_repo(
    repo_path: Path,
    catalog: Catalog,
    config: ScannerConfig,
    scan_timestamp: str,
    *,
    rotation_salt: bytes | None = None,
    author_salt: bytes | None = None,
) -> tuple[RepoContext, list[Finding], int, int]:
    repo_context = build_repo_context(repo_path)
    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0
    anchor_ordinals: dict[tuple[str, str, str], int] = {}

    for wf in walk_repo_files(repo_path, config):
        try:
            text = wf.abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            files_skipped += 1
            continue

        detections = scan_text(
            text, catalog, config, is_lockfile=wf.is_lockfile, rotation_salt=rotation_salt
        )
        files_scanned += 1
        if not detections:
            continue

        is_tracked = False
        is_ignored = False
        blame_map: dict[int, GitBlameInfo] = {}
        if repo_context.is_git_repo:
            is_tracked = is_path_tracked(repo_path, wf.repo_relative_posix)
            if is_tracked:
                line_numbers = {d.line_number for d in detections}
                blame_map = blame_lines(repo_path, wf.repo_relative_posix, line_numbers)
            else:
                is_ignored = is_path_gitignored(repo_path, wf.repo_relative_posix)

        in_test_path = _looks_like_test_path(wf.repo_relative_posix)
        file_lines = text.splitlines()

        for d in detections:
            blame_info = blame_map.get(d.line_number)
            if blame_info is not None:
                provenance_state = blame_info.provenance_state
                commit_sha = blame_info.commit_sha
                author_name = blame_info.author_name
                author_email = blame_info.author_email
                author_timestamp = blame_info.author_timestamp
            else:
                provenance_state = (
                    ProvenanceState.NOT_A_REPO
                    if not repo_context.is_git_repo
                    else ProvenanceState.UNTRACKED
                )
                commit_sha = author_name = author_email = author_timestamp = None

            if author_salt is not None:
                if author_name is not None:
                    author_name = hash_author(author_salt, author_name)
                if author_email is not None:
                    author_email = hash_author(author_salt, author_email)

            line_text = (
                file_lines[d.line_number - 1] if d.line_number - 1 < len(file_lines) else ""
            )
            anchor = build_anchor(line_text, d.column_start, d.match_length)
            anchor_key = (wf.repo_relative_posix, d.pattern_id, anchor)
            ordinal = anchor_ordinals.get(anchor_key, 0)
            anchor_ordinals[anchor_key] = ordinal + 1
            finding_id = compute_finding_id(
                repo_context.repo_id, wf.repo_relative_posix, d.pattern_id, anchor, ordinal
            )

            findings.append(
                Finding(
                    finding_id=finding_id,
                    repo_id=repo_context.repo_id,
                    repo_path=str(repo_path),
                    file_path=wf.repo_relative_posix,
                    line_number=d.line_number,
                    column_start=d.column_start,
                    match_length=d.match_length,
                    matched_pattern_type=d.pattern_id,
                    pattern_id=d.pattern_id,
                    provider=d.provider,
                    confidence=d.confidence,
                    detector=d.detector,
                    entropy_bits=d.entropy_bits,
                    commit_sha=commit_sha,
                    author_name=author_name,
                    author_email=author_email,
                    author_timestamp=author_timestamp,
                    provenance_state=provenance_state,
                    is_git_tracked=is_tracked,
                    is_gitignored=is_ignored,
                    in_test_path=in_test_path,
                    scan_timestamp=scan_timestamp,
                    secret_fingerprint=d.secret_fingerprint,
                )
            )

    return repo_context, findings, files_scanned, files_skipped


def run_scan(
    repo_paths: list[Path],
    catalog: Catalog,
    config: ScannerConfig,
    *,
    rotation_salt: bytes | None = None,
    author_salt: bytes | None = None,
) -> tuple[list[Finding], ScanSummary, set[str]]:
    """Returns (findings, summary, scanned_repo_ids). `scanned_repo_ids`
    includes every repo successfully scanned even if it produced zero
    findings -- the caller needs the full set to correctly resolve stale
    findings for repos that are now clean (PLAN.md section 8 diff semantics).
    """
    scan_timestamp = datetime.now(UTC).isoformat()
    summary = ScanSummary()
    all_findings: list[Finding] = []
    scanned_repo_ids: set[str] = set()

    with ThreadPoolExecutor(max_workers=max(1, config.jobs)) as pool:
        futures = {
            pool.submit(
                scan_repo,
                repo_path,
                catalog,
                config,
                scan_timestamp,
                rotation_salt=rotation_salt,
                author_salt=author_salt,
            ): repo_path
            for repo_path in repo_paths
        }
        for future in as_completed(futures):
            repo_path = futures[future]
            try:
                repo_context, findings, files_scanned, files_skipped = future.result()
            except Exception as exc:  # noqa: BLE001 - one repo's failure must not sink the scan
                summary.errors.append(f"{repo_path}: {exc}")
                continue
            all_findings.extend(findings)
            scanned_repo_ids.add(repo_context.repo_id)
            summary.repos_scanned += 1
            summary.files_scanned += files_scanned
            summary.files_skipped += files_skipped

    summary.findings_total = len(all_findings)
    return all_findings, summary, scanned_repo_ids
