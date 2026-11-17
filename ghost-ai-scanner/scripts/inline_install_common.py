"""Phase 1 (installer-architecture proposal, 2026-11-17) build step.

Four of the five installer entry points ship as a single standalone .ps1
file -- there is no sibling file on the user's machine for a real
`Import-Module` to find. RavenInstallCommon.psm1 stays the single source of
truth in the repo; this script inlines its function bodies directly into a
target single-file script at BUILD time, so the shipped artifact is still
one file, but its logic is de-duplicated at the source.

CoworkDLP is the one entry point that does NOT need this: it ships inside a
zip with multiple files, so a real Import-Module against a sibling file on
disk works as-is there.

Usage:
    python tools/inline_install_common.py \
        --module agent/install/RavenInstallCommon.psm1 \
        --target hub/templates/raven_install.ps1.template \
        --out    hub/templates/raven_install.ps1.template.built

Idempotent and marker-guarded: re-running against an already-inlined file
replaces the previously-inlined block instead of duplicating it, so this is
safe to run on every build, not just once.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

START_MARKER = "# >>> RavenInstallCommon (inlined by tools/inline_install_common.py -- do not edit by hand, edit the .psm1 source) >>>"
END_MARKER = "# <<< RavenInstallCommon (inlined) <<<"


def extract_functions(module_text: str) -> str:
    """Strip the module-only wrapper (Export-ModuleMember, the #Requires
    line, the module's own header comment) and return just the function
    bodies -- the part that's actually safe to paste into another script.
    """
    # Drop everything from Export-ModuleMember to end of file.
    body = re.split(r"^Export-ModuleMember\b.*$", module_text, flags=re.MULTILINE | re.DOTALL)[0]
    # Drop the #Requires line -- the target script has its own.
    body = re.sub(r"^#Requires -Version.*\n", "", body, flags=re.MULTILINE)
    return body.strip() + "\n"


def inline(target_text: str, functions_text: str) -> str:
    block = f"{START_MARKER}\n{functions_text}\n{END_MARKER}"

    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        re.DOTALL,
    )
    if pattern.search(target_text):
        # Re-run: replace the previously inlined block in place, so repeated
        # builds never duplicate it and always carry the CURRENT module
        # source, not a stale copy from the first build.
        #
        # re.sub(block, ...) (passing `block` directly as the replacement)
        # treats it as a regex REPLACEMENT TEMPLATE, where a literal
        # backslash sequence in the module source (e.g. a Windows path in a
        # comment) can raise "bad escape" or be silently misinterpreted.
        # The lambda makes `block` a literal string substitution instead.
        return pattern.sub(lambda _m: block, target_text)

    # First run: insert right after the first $ErrorActionPreference line
    # (every entry point sets this as its first real statement, after the
    # header comment block) -- i.e. before any installer-specific logic,
    # exactly where Assert-RavenRelaunched64Bit must run from.
    lines = target_text.splitlines(keepends=True)
    insert_at = None
    for i, line in enumerate(lines):
        if line.strip().startswith("$ErrorActionPreference"):
            insert_at = i + 1
            break
    if insert_at is None:
        raise SystemExit(
            "Could not find a $ErrorActionPreference line to anchor the inline block to -- "
            "refusing to guess a location. Add one near the top of the target script."
        )
    lines.insert(insert_at, "\n" + block + "\n")
    return "".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--module", required=True, type=Path)
    ap.add_argument("--target", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument(
        "--check",
        action="store_true",
        help=(
            "Don't write anything -- regenerate from --module and --target "
            "in memory and exit non-zero if the result differs from what's "
            "currently on disk at --target (i.e. the committed inlined copy "
            "has drifted from the .psm1 source). Addresses review feedback "
            "(M2, PR #702): nothing previously guarded the committed inlined "
            "copies against drifting out of sync with the module."
        ),
    )
    args = ap.parse_args()

    if not args.check and args.out is None:
        ap.error("--out is required unless --check is given")

    module_text = args.module.read_text(encoding="utf-8")
    target_text = args.target.read_text(encoding="utf-8")

    functions_text = extract_functions(module_text)
    result = inline(target_text, functions_text)

    if args.check:
        if result == target_text:
            print(f"OK: {args.target} already matches {args.module}")
            return
        print(
            f"DRIFT: {args.target} does NOT match what {args.module} would "
            f"produce -- re-run without --check and commit the result."
        )
        sys.exit(1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(result, encoding="utf-8", newline="\n")
    print(f"Wrote {args.out} ({len(result)} bytes, inlined from {args.module})")


if __name__ == "__main__":
    main()
