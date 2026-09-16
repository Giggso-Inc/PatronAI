"""apikey_scanner: detect hardcoded API keys and secrets. Reports detection
metadata only -- repo, file, line, pattern type, git provenance. Secret
values are never collected, stored, or exported. See PLAN.md section 1.1.
"""

__version__ = "0.1.0"
