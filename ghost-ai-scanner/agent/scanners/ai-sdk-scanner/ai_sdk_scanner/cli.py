"""CLI entry point. PLAN.md section 8.4.

Exit codes: 0 clean, 1 one or more manifests failed to parse, 2 target
path not found/readable, 3 bad usage.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from ai_sdk_scanner import __version__
from ai_sdk_scanner.catalog.loader import Catalog, load_catalog
from ai_sdk_scanner.errors import CatalogError
from ai_sdk_scanner.models import ScanReport
from ai_sdk_scanner.pipeline import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-sdk-scanner",
        description=(
            "Inventory every dependency declared in a repository's manifests, "
            "flagging AI/ML libraries via a curated catalog. Findings are evidence "
            "of what code declares, not a judgment (see PLAN.md)."
        ),
    )
    parser.add_argument(
        "repo_path", nargs="?", default=".", help="Repository to scan (default: current directory)."
    )
    parser.add_argument("--format", choices=("jsonl", "json", "csv", "table"), default="jsonl")
    parser.add_argument("--output", default=None, help="Write to this path instead of stdout.")
    parser.add_argument("--repo-id", default=None, help="Override the derived repo_id.")
    parser.add_argument("--catalog", default=None, help="Path to a custom catalog JSON file.")
    parser.add_argument(
        "--ai-only", action="store_true",
        help="Report only dependencies that match the AI/ML catalog. "
             "By default EVERY dependency is reported, with AI ones flagged "
             "via is_ai_related / category.",
    )
    parser.add_argument("--include-vendored", action="store_true")
    parser.add_argument(
        "--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True
    )
    parser.add_argument("--include-transitive", action="store_true")
    parser.add_argument("--with-file-commits", action="store_true")
    parser.add_argument("--max-depth", type=int, default=None)

    system = parser.add_argument_group("system-wide scan")
    system.add_argument(
        "--system", action="store_true",
        help="Scan the whole machine: discover every project, then scan each one. "
             "Ignores the repo_path argument in favour of --roots.",
    )
    system.add_argument(
        "--roots", action="append", default=None,
        help="Repeatable. Scan root(s) for --system mode. Defaults to every fixed drive.",
    )
    system.add_argument(
        "--home-only", action="store_true",
        help="--system mode: scan only the user's home directory instead of all drives.",
    )
    system.add_argument(
        "--max-projects", type=int, default=None,
        help="--system mode: stop discovery after this many projects (safety valve).",
    )
    system.add_argument(
        "--all-projects", action="store_true",
        help="--system mode: include projects with zero reported dependencies "
             "(default: omit them).",
    )
    system.add_argument(
        "--progress", action="store_true",
        help="--system mode: print discovery/scan progress to stderr.",
    )
    system.add_argument(
        "--workers", type=int, default=None,
        help="--system mode: thread-pool size for per-project scans "
             "(default: min(16, cpu_count * 2)).",
    )
    system.add_argument(
        "--max-files-per-project", type=int, default=None,
        help="--system mode: per-project file budget for manifest discovery "
             "(default 20000). Projects hitting it are flagged walk_truncated. "
             "Pass 0 for unlimited.",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--version", action="version", version=f"ai-sdk-scanner {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = logging.WARNING if args.verbose == 0 else (
        logging.INFO if args.verbose == 1 else logging.DEBUG
    )
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")

    try:
        catalog = load_catalog(Path(args.catalog) if args.catalog else None)
    except CatalogError as exc:
        print(f"Catalog error: {exc}", file=sys.stderr)
        return 3

    if args.system:
        return _run_system_mode(args, catalog)

    repo_root = Path(args.repo_path).resolve()
    if not repo_root.is_dir():
        print(f"Target path does not exist or is not a directory: {repo_root}", file=sys.stderr)
        return 2

    t0 = time.monotonic()
    report = run_scan(
        repo_root,
        catalog,
        explicit_repo_id=args.repo_id,
        include_vendored=args.include_vendored,
        respect_gitignore=args.respect_gitignore,
        include_transitive=args.include_transitive,
        with_file_commits=args.with_file_commits,
        max_depth=args.max_depth,
        ai_only=args.ai_only,
    )
    duration_ms = int((time.monotonic() - t0) * 1000)

    from dataclasses import replace

    report = replace(report, duration_ms=duration_ms)

    output = _render(report, args)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        sys.stdout.write(output)

    if report.errors:
        return 1
    return 0


def _resolve_max_files(value: int | None) -> int | None:
    """None -> module default; 0 -> unlimited; otherwise the given budget."""
    from ai_sdk_scanner.system_scan import _DEFAULT_MAX_FILES_PER_PROJECT

    if value is None:
        return _DEFAULT_MAX_FILES_PER_PROJECT
    return None if value == 0 else value


def _run_system_mode(args: argparse.Namespace, catalog: Catalog) -> int:
    """--system: discover every project on the machine, then scan each."""
    from ai_sdk_scanner.system_scan import run_system_scan

    roots: list[Path] | None = None
    if args.roots:
        roots = []
        for raw in args.roots:
            p = Path(raw).resolve()
            if not p.is_dir():
                print(f"--roots path is not a directory: {p}", file=sys.stderr)
                return 2
            roots.append(p)

    report = run_system_scan(
        catalog,
        roots=roots,
        all_drives=not args.home_only,
        max_depth=args.max_depth if args.max_depth is not None else 12,
        max_projects=args.max_projects,
        include_transitive=args.include_transitive,
        include_vendored=args.include_vendored,
        respect_gitignore=args.respect_gitignore,
        with_file_commits=args.with_file_commits,
        only_with_matches=not args.all_projects,
        workers=args.workers,
        max_files_per_project=_resolve_max_files(args.max_files_per_project),
        ai_only=args.ai_only,
        progress=args.progress,
    )

    from ai_sdk_scanner.report import system as system_report

    if args.format == "table":
        output = system_report.render_table(report)
    elif args.format == "json":
        output = system_report.to_json(report)
    elif args.format == "csv":
        output = system_report.to_csv(report)
    else:
        output = system_report.to_jsonl(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        sys.stdout.write(output)

    if any(p.errors for p in report.projects):
        return 1
    return 0


def _render(report: ScanReport, args: argparse.Namespace) -> str:
    if args.format == "table":
        from ai_sdk_scanner.report.table import render_table

        return render_table(report)
    from ai_sdk_scanner.report.structured import to_csv, to_json, to_jsonl

    if args.format == "json":
        return to_json(report)
    if args.format == "csv":
        return to_csv(report)
    return to_jsonl(report)


if __name__ == "__main__":
    sys.exit(main())
