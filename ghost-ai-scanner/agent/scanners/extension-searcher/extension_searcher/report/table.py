"""Human-readable table renderer. PLAN.md section 10.1.

Grouped Browser -> Profile -> Extension. Disabled rows are marked with a
leading `.`, sideloaded with `!` — glyphs, not colour alone, so the output
survives piping and screen readers. Extension IDs are never truncated.
"""

from __future__ import annotations

import os
import shutil
import sys

from extension_searcher.models import Confidence, ExtensionRecord, InstallOrigin, ScanReport

_MIN_WIDTH = 80


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _dim(text: str, enabled: bool) -> str:
    return f"\x1b[2m{text}\x1b[0m" if enabled else text


def render_table(report: ScanReport, *, no_color: bool = False) -> str:
    width = max(shutil.get_terminal_size(fallback=(_MIN_WIDTH, 24)).columns, _MIN_WIDTH)
    color = _use_color() and not no_color
    name_width = max(20, width - 55)

    lines: list[str] = []
    lines.append(f"Extension Searcher — {report.host} ({report.os_name})")
    lines.append(_dim(f"scanned {report.started_at} in {report.duration_ms}ms", color))
    lines.append("")

    found_browsers = [b for b in report.browsers if b.found]
    absent_browsers = [b for b in report.browsers if not b.found]

    for browser in found_browsers:
        browser_extensions = [
            r for r in report.extensions if r.browser == browser.name
        ]
        marker = " [unverified paths]" if browser.unverified else ""
        lines.append(f"== {browser.name}{marker} — {len(browser_extensions)} extension(s) ==")

        by_profile: dict[str, list[ExtensionRecord]] = {}
        for r in browser_extensions:
            by_profile.setdefault(r.profile_dir, []).append(r)

        for profile_dir, records in by_profile.items():
            profile_label = profile_dir
            lines.append(f"  -- Profile: {profile_label} --")
            header = (
                f"    {'':1} {'Name':<{name_width}} {'Version':<10} "
                f"{'State':<8} {'Origin':<12} ID"
            )
            lines.append(_dim(header, color))
            for r in sorted(records, key=lambda x: x.name.lower()):
                glyph = "." if r.enabled is False else (
                    "!" if r.install_origin == InstallOrigin.SIDELOADED else " "
                )
                if r.enabled is False:
                    state = "disabled"
                elif r.enabled:
                    state = "enabled"
                else:
                    state = "unknown"
                name = r.name if len(r.name) <= name_width else r.name[: name_width - 1] + "…"
                partial = " (partial)" if r.confidence != Confidence.FULL else ""
                lines.append(
                    f"    {glyph} {name:<{name_width}} {r.version:<10} {state:<8}"
                    f" {r.install_origin.value:<12} {r.extension_id}{partial}"
                )
        lines.append("")

    if absent_browsers:
        lines.append("Not found on this host:")
        for b in absent_browsers:
            lines.append(_dim(f"  - {b.name}", color))
        lines.append("")

    s = report.summary
    lines.append(
        f"Summary: {s.browsers_found} browser(s), {s.profiles} profile(s), "
        f"{s.extensions} extension(s) ({s.unique_extensions} unique), "
        f"{s.disabled} disabled, {s.sideloaded} sideloaded"
    )
    if report.unverified_paths:
        lines.append(
            _dim(
                f"{len(report.unverified_paths)} path(s) unverified on a real host "
                "(no macOS host available — see PLAN.md section 15.1)",
                color,
            )
        )
    if report.errors:
        lines.append(_dim(f"{len(report.errors)} error(s) — see --format=json for detail", color))

    return "\n".join(lines) + "\n"
