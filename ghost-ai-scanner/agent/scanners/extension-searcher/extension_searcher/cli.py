"""CLI entry point. PLAN.md section 10.

Exit codes: 0 clean, 1 completed with errors[], 2 no browsers found, 3 bad usage.
"""

from __future__ import annotations

import argparse
import logging
import platform
import socket
import sys
import time
from datetime import UTC, datetime

from extension_searcher import __version__
from extension_searcher.discovery import run_scan
from extension_searcher.models import InstallOrigin, ScanReport, ScanSummary
from extension_searcher.platform_probe import current_os
from extension_searcher.registry import ALL_BROWSERS, BrowserSpec

HIGH_PRIVILEGE_PATTERNS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="extension-searcher",
        description="Cross-platform browser extension inventory (PLAN.md).",
    )
    parser.add_argument(
        "--format", choices=("table", "json", "jsonl", "csv"), default="table"
    )
    parser.add_argument("--output", default=None, help="Write to this path instead of stdout.")
    parser.add_argument("--browser", action="append", default=None, help="Repeatable filter.")
    parser.add_argument(
        "--engine", choices=("chromium", "gecko", "webkit", "trident", "all"), default="all"
    )
    parser.add_argument("--include-builtin", action="store_true")
    parser.add_argument("--include-themes", action="store_true")
    parser.add_argument("--deep", action="store_true", help="Not yet implemented (P4/P6).")
    parser.add_argument(
        "--extra-root", action="append", default=None, help="Not yet implemented (P6)."
    )
    parser.add_argument("--no-state", action="store_true")
    parser.add_argument("--cache", default=None, help="Not yet implemented.")
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--risk", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--version", action="version", version=f"extension-searcher {__version__}")
    return parser


def _filter_specs(args: argparse.Namespace) -> tuple[BrowserSpec, ...]:
    specs = ALL_BROWSERS
    if args.engine != "all":
        specs = tuple(s for s in specs if s.engine.value == args.engine)
    if args.browser:
        wanted = {b.lower() for b in args.browser}
        specs = tuple(s for s in specs if s.name.lower() in wanted)
    return specs


def _extra_engine_flags(args: argparse.Namespace) -> tuple[bool, bool]:
    """Whether the (non-registry) webkit/trident parsers should run at all,
    given --engine and --browser. Actual OS gating happens in discovery.py."""
    engine_ok_webkit = args.engine in ("all", "webkit")
    engine_ok_trident = args.engine in ("all", "trident")
    if not args.browser:
        return engine_ok_webkit, engine_ok_trident
    wanted = {b.lower() for b in args.browser}
    return (
        engine_ok_webkit and "safari" in wanted,
        engine_ok_trident and "internet explorer" in wanted,
    )


def _annotate_risk(report: ScanReport) -> ScanReport:
    """CLI `--risk`: tag records whose permissions cover most/all sites."""
    from dataclasses import replace

    annotated = []
    for r in report.extensions:
        risky = any(
            pat in perm
            for perm in (*r.permissions, *r.host_permissions)
            for pat in HIGH_PRIVILEGE_PATTERNS
        )
        if risky and "high_privilege_host_access" not in r.warnings:
            annotated.append(replace(r, warnings=(*r.warnings, "high_privilege_host_access")))
        else:
            annotated.append(r)
    return replace(report, extensions=tuple(annotated))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = logging.WARNING if args.verbose == 0 else (
        logging.INFO if args.verbose == 1 else logging.DEBUG
    )
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")

    if args.deep:
        logging.getLogger(__name__).warning("--deep is not yet implemented; ignoring.")
    if args.cache:
        logging.getLogger(__name__).warning("--cache is not yet implemented; ignoring.")
    if args.extra_root:
        logging.getLogger(__name__).warning("--extra-root is not yet implemented; ignoring.")

    specs = _filter_specs(args)
    include_webkit, include_trident = _extra_engine_flags(args)
    if not specs and not include_webkit and not include_trident:
        print("No browsers match the given --browser/--engine filters.", file=sys.stderr)
        return 3

    start = datetime.now(UTC)
    t0 = time.monotonic()
    result = run_scan(
        specs,
        include_builtin=args.include_builtin,
        include_themes=args.include_themes,
        include_state=not args.no_state,
        include_webkit=include_webkit,
        include_trident=include_trident,
        workers=args.workers,
    )
    duration_ms = int((time.monotonic() - t0) * 1000)
    finish = datetime.now(UTC)

    unique_ids = {r.extension_id for r in result.extensions}
    summary = ScanSummary(
        browsers_found=sum(1 for b in result.browsers if b.found),
        profiles=sum(len(b.profiles) for b in result.browsers),
        extensions=len(result.extensions),
        unique_extensions=len(unique_ids),
        disabled=sum(1 for r in result.extensions if r.enabled is False),
        sideloaded=sum(
            1 for r in result.extensions if r.install_origin == InstallOrigin.SIDELOADED
        ),
    )

    report = ScanReport(
        host=socket.gethostname(),
        os_name=f"{current_os()} ({platform.platform()})",
        started_at=start.isoformat(),
        finished_at=finish.isoformat(),
        tool_version=__version__,
        duration_ms=duration_ms,
        browsers=result.browsers,
        extensions=result.extensions,
        errors=result.errors,
        summary=summary,
        unverified_paths=result.unverified_paths,
    )

    if args.risk:
        report = _annotate_risk(report)

    output = _render(report, args)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        sys.stdout.write(output)

    if summary.browsers_found == 0:
        return 2
    if report.errors:
        return 1
    return 0


def _render(report: ScanReport, args: argparse.Namespace) -> str:
    if args.format == "table":
        from extension_searcher.report.table import render_table

        return render_table(report, no_color=args.no_color)
    from extension_searcher.report.structured import to_csv, to_json, to_jsonl

    if args.format == "json":
        return to_json(report)
    if args.format == "jsonl":
        return to_jsonl(report)
    return to_csv(report)


if __name__ == "__main__":
    sys.exit(main())
