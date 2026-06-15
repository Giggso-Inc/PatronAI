#!/usr/bin/env python3
# =============================================================
# FILE: scripts/refresh_eni_cache.py
# VERSION: 2.0.0
# UPDATED: 2026-06-11
# PURPOSE: OCI migration shim — delegates to refresh_vnic_cache.py
#          Kept to avoid breakage of existing cron jobs / scripts.
# =============================================================
import subprocess, sys
result = subprocess.run(
    [sys.executable, __file__.replace("refresh_eni_cache.py", "refresh_vnic_cache.py")]
    + sys.argv[1:],
    cwd=__file__[:__file__.rfind("/")]
)
sys.exit(result.returncode)
