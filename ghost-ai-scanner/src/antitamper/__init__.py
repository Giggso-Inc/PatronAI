# =============================================================
# FILE: src/antitamper/__init__.py
# PURPOSE: Patron golden-hash anti-tamper (Cowork 90_antitamper parity).
# =============================================================

from antitamper.scanner import (
    build_baseline,
    load_baseline,
    restore,
    scan,
    run_once,
)

__all__ = [
    "build_baseline",
    "load_baseline",
    "restore",
    "scan",
    "run_once",
]
