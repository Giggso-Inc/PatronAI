# =============================================================
# FILE: tests/vendor/conftest.py
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Make the three vendored companion packages
#          (agent/scanners/{ai-sdk-scanner,extension-searcher,
#          apikey-scanner}/) importable by their own unmodified test
#          suites, without an `pip install -e` step. Same idea as the
#          top-level tests/conftest.py inserting src/ onto sys.path —
#          extended here to three sibling package roots instead of one.
#          Each package's tests do a plain `from ai_sdk_scanner import
#          ...`-style import, which only resolves once that package's
#          own root directory (the one holding pyproject.toml and the
#          importable package folder) is on sys.path.
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial. Phase 1 of the scanner-graft plan.
# =============================================================

import sys
from pathlib import Path

_SCANNERS = Path(__file__).resolve().parents[2] / "agent" / "scanners"

for _pkg_root in ("ai-sdk-scanner", "extension-searcher", "apikey-scanner"):
    _path = str(_SCANNERS / _pkg_root)
    if _path not in sys.path:
        sys.path.insert(0, _path)
