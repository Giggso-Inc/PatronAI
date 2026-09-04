"""CLI surface. PLAN.md section 9.

Exit codes: 0 success (regardless of findings -- section 1.2), 1 internal
error, 2 bad usage/config. There is no findings-based exit code in v1.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

from apikey_scanner import __version__
from apikey_scanner.catalog.loader import load_catalog
from apikey_scanner.config import ScannerConfig, load_config
from apikey_scanner.discovery import discover_all_repos
from apikey_scanner.errors import ApiKeyScannerError
from apikey_scanner.pipeline import run_scan
from apikey_scanner.report.structured import to_csv, to_json, to_jsonl
from apikey_scanner.report.table import to_table
from apikey_scanner.secret_salt import load_or_create_salt
from apikey_scanner.store.diff import diff_scans
from apikey_scanner.store.sqlite_store import SqliteStore


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apikey-scanner",
        description=(
            "Detect hardcoded API keys and secrets across git repositories. "
            "Reports detection metadata ONLY -- repo, file, line, pattern type, "
            "git provenance. Secret values are never collected, stored, or "
            "exported. This tool reports evidence, not a verdict: finding "
            "secrets always exits 0."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan configured roots and record findings")
    scan_p.add_argument("--root", action="append", dest="roots", default=None)
    scan_p.add_argument("--config", dest="config_path", default=None)
    scan_p.add_argument("--db", dest="db_path", default=None)
    scan_p.add_argument("--jobs", type=int, default=None)
    scan_p.add_argument("--track-rotation", action="store_true", default=None)
    scan_p.add_argument("--hash-authors", action="store_true", default=None)
    scan_p.add_argument("--no-entropy", action="store_true", default=False)

    report_p = sub.add_parser("report", help="print findings from the database")
    report_p.add_argument("--db", dest="db_path", default=None)
    report_p.add_argument(
        "--format", dest="fmt", choices=["table", "json", "jsonl", "csv"], default="table"
    )
    report_p.add_argument("--repo", dest="repo_id", default=None)
    report_p.add_argument("--confidence", dest="confidence", default=None)
    report_p.add_argument("--since", dest="since_scan_id", type=int, default=None)
    report_p.add_argument("--new-only", action="store_true", default=False)

    diff_p = sub.add_parser("diff", help="compare findings between two scans")
    diff_p.add_argument("--db", dest="db_path", default=None)
    diff_p.add_argument("--from", dest="from_scan_id", type=int, required=True)
    diff_p.add_argument("--to", dest="to_scan_id", type=int, required=True)

    allow_p = sub.add_parser("allowlist", help="manage allowlisted findings")
    allow_sub = allow_p.add_subparsers(dest="allow_command", required=True)
    allow_add = allow_sub.add_parser("add")
    allow_add.add_argument("finding_id")
    allow_add.add_argument("--reason", required=True)
    allow_add.add_argument("--db", dest="db_path", default=None)
    allow_list = allow_sub.add_parser("list")
    allow_list.add_argument("--db", dest="db_path", default=None)
    allow_remove = allow_sub.add_parser("remove")
    allow_remove.add_argument("finding_id")
    allow_remove.add_argument("--db", dest="db_path", default=None)

    patterns_p = sub.add_parser("patterns", help="list catalog patterns")
    patterns_sub = patterns_p.add_subparsers(dest="patterns_command", required=True)
    patterns_list = patterns_sub.add_parser("list")
    patterns_list.add_argument("--provider", default=None)

    scans_p = sub.add_parser("scans", help="list past scans")
    scans_sub = scans_p.add_subparsers(dest="scans_command", required=True)
    scans_list = scans_sub.add_parser("list")
    scans_list.add_argument("--db", dest="db_path", default=None)

    return parser


def _resolve_config(args: argparse.Namespace) -> ScannerConfig:
    config_path = getattr(args, "config_path", None)
    config = load_config(config_path)
    if getattr(args, "roots", None):
        config.roots = tuple(args.roots)
    if getattr(args, "db_path", None):
        config.db_path = args.db_path
    if getattr(args, "jobs", None) is not None:
        config.jobs = args.jobs
    if getattr(args, "track_rotation", None):
        config.track_rotation = True
    if getattr(args, "hash_authors", None):
        config.hash_authors = True
    if getattr(args, "no_entropy", False):
        config.enable_entropy = False
    return config


def _ensure_db_gitignored(db_path: Path) -> None:
    gitignore = db_path.parent / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*\n", encoding="utf-8")


def cmd_scan(args: argparse.Namespace) -> int:
    config = _resolve_config(args)
    if not config.roots:
        print("error: no scan roots configured (use --root or a --config file)", file=sys.stderr)
        return 2

    catalog = load_catalog()
    repo_paths = list(discover_all_repos(config))
    if not repo_paths:
        print(f"no git repositories found under {config.roots}", file=sys.stderr)

    db_path = Path(config.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _ensure_db_gitignored(db_path)

    rotation_salt = None
    author_salt = None
    if config.track_rotation or config.hash_authors:
        salt = load_or_create_salt(db_path.parent / "salt")
        if config.track_rotation:
            rotation_salt = salt
        if config.hash_authors:
            author_salt = salt

    import time

    start = time.monotonic()
    findings, summary, scanned_repo_ids = run_scan(
        repo_paths, catalog, config, rotation_salt=rotation_salt, author_salt=author_salt
    )
    duration_ms = int((time.monotonic() - start) * 1000)

    for err in summary.errors:
        print(f"warning: {err}", file=sys.stderr)

    with SqliteStore(db_path) as store:
        scan_id = store.start_scan(
            scan_timestamp=datetime.now(UTC).isoformat(),
            tool_version=__version__,
            catalog_version=catalog.version,
            roots_json=json.dumps(list(config.roots)),
            host=socket.gethostname(),
        )
        store.record_findings(scan_id, findings, scanned_repo_ids)
        store.finish_scan(
            scan_id,
            repos_scanned=summary.repos_scanned,
            files_scanned=summary.files_scanned,
            files_skipped=summary.files_skipped,
            findings_total=summary.findings_total,
            duration_ms=duration_ms,
        )

    print(
        f"scan {scan_id}: {summary.repos_scanned} repo(s), {summary.files_scanned} file(s) "
        f"scanned, {summary.findings_total} finding(s), {duration_ms} ms"
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    db_path = Path(args.db_path or ScannerConfig().db_path)
    if not db_path.exists():
        print(
            f"no findings database at {db_path} -- run 'apikey-scanner scan' first",
            file=sys.stderr,
        )
        return 2

    confidences = tuple(args.confidence.split(",")) if args.confidence else None
    with SqliteStore(db_path) as store:
        rows = store.query_findings(
            repo_id=args.repo_id,
            confidences=confidences,
            since_scan_id=args.since_scan_id if args.new_only else None,
        )

    from apikey_scanner.models import Confidence, Detector, Finding, ProvenanceState

    findings = [
        Finding(
            finding_id=r["finding_id"],
            repo_id=r["repo_id"],
            repo_path=r["repo_path"],
            file_path=r["file_path"],
            line_number=r["line_number"],
            column_start=r["column_start"],
            match_length=r["match_length"],
            matched_pattern_type=r["matched_pattern_type"],
            pattern_id=r["pattern_id"],
            provider=r["provider"],
            confidence=Confidence(r["confidence"]),
            detector=Detector(r["detector"]),
            entropy_bits=r["entropy_bits"],
            commit_sha=r["commit_sha"],
            author_name=r["author_name"],
            author_email=r["author_email"],
            author_timestamp=r["author_timestamp"],
            provenance_state=ProvenanceState(r["provenance_state"]),
            is_git_tracked=bool(r["is_git_tracked"]),
            is_gitignored=bool(r["is_gitignored"]),
            in_test_path=bool(r["in_test_path"]),
            scan_timestamp=r["scan_timestamp"],
            secret_fingerprint=r["secret_fingerprint"],
        )
        for r in rows
    ]

    if args.fmt == "table":
        print(to_table(findings), end="")
    elif args.fmt == "json":
        print(to_json(findings))
    elif args.fmt == "jsonl":
        print(to_jsonl(findings))
    elif args.fmt == "csv":
        print(to_csv(findings), end="")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    db_path = Path(args.db_path or ScannerConfig().db_path)
    with SqliteStore(db_path) as store:
        diff = diff_scans(store, args.from_scan_id, args.to_scan_id)
    print(f"new: {len(diff.new)}")
    for fid in diff.new:
        print(f"  + {fid}")
    print(f"resolved: {len(diff.resolved)}")
    for fid in diff.resolved:
        print(f"  - {fid}")
    print(f"persisting: {len(diff.persisting)}")
    return 0


def cmd_allowlist(args: argparse.Namespace) -> int:
    db_path = Path(args.db_path or ScannerConfig().db_path)
    with SqliteStore(db_path) as store:
        if args.allow_command == "add":
            store.add_allowlist(
                args.finding_id, args.reason, None, datetime.now(UTC).isoformat()
            )
            print(f"allowlisted {args.finding_id}")
        elif args.allow_command == "list":
            for row in store.list_allowlist():
                print(f"{row['finding_id']}  {row['reason']}  {row['added_at']}")
        elif args.allow_command == "remove":
            store.remove_allowlist(args.finding_id)
            print(f"removed {args.finding_id} from allowlist")
    return 0


def cmd_patterns(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    for spec in catalog.specs.values():
        if args.provider and spec.provider != args.provider:
            continue
        print(f"{spec.id:35s} {spec.provider:15s} {spec.confidence.value:8s} {spec.kind}")
    return 0


def cmd_scans(args: argparse.Namespace) -> int:
    db_path = Path(args.db_path or ScannerConfig().db_path)
    with SqliteStore(db_path) as store:
        for row in store.list_scans():
            print(
                f"{row['scan_id']:4d}  {row['scan_timestamp']}  "
                f"repos={row['repos_scanned']} files={row['files_scanned']} "
                f"findings={row['findings_total']}"
            )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "report":
            return cmd_report(args)
        if args.command == "diff":
            return cmd_diff(args)
        if args.command == "allowlist":
            return cmd_allowlist(args)
        if args.command == "patterns":
            return cmd_patterns(args)
        if args.command == "scans":
            return cmd_scans(args)
        parser.print_help()
        return 2
    except ApiKeyScannerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
