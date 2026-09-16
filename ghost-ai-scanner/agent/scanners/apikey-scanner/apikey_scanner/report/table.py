"""Human-readable table output. Stdlib only, no external deps."""

from __future__ import annotations

from apikey_scanner.models import Finding
from apikey_scanner.report.structured import FOOTER_NOTE

_COLUMNS = (
    ("repo_id", 28),
    ("file_path", 40),
    ("line_number", 6),
    ("matched_pattern_type", 26),
    ("confidence", 8),
    ("provenance_state", 18),
)


def _truncate(value: str, width: int) -> str:
    # ASCII "..." rather than a Unicode ellipsis: the default Windows
    # console codepage (cp1252/cp850) mangles U+2026 into a replacement
    # character, which is exactly the kind of corruption this table must
    # never produce for a repo_id/file_path a user needs to act on.
    return value if len(value) <= width else value[: width - 3] + "..."


def to_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings.\n" + FOOTER_NOTE + "\n"

    lines: list[str] = []
    header = "  ".join(name.upper().ljust(width) for name, width in _COLUMNS)
    lines.append(header)
    lines.append("-" * len(header))
    for f in findings:
        row_values = {
            "repo_id": f.repo_id,
            "file_path": f.file_path,
            "line_number": str(f.line_number),
            "matched_pattern_type": f.matched_pattern_type,
            "confidence": f.confidence.value,
            "provenance_state": f.provenance_state.value,
        }
        lines.append(
            "  ".join(
                _truncate(row_values[name], width).ljust(width) for name, width in _COLUMNS
            )
        )
    lines.append("")
    lines.append(f"{len(findings)} finding(s).")
    lines.append(FOOTER_NOTE)
    return "\n".join(lines) + "\n"
