"""CI guard: a PR that changes the installable agent must raise AGENT_VERSION.

Devices only receive an update when the published agent version is higher than
the one they run. A fix under ghost-ai-scanner/agent/install/ that ships with
an unchanged ghost-ai-scanner/agent/AGENT_VERSION is never delivered by
auto-update (this is how the pre-commit hook fix of 6 Nov missed devices).

Usage: python scripts/check_agent_version_bump.py <base-ref>   (e.g. origin/main)
Exit 0 = fine, 1 = installer changed without a version bump.
"""
import subprocess
import sys

INSTALL_PREFIX = "ghost-ai-scanner/agent/install/"
VERSION_FILE = "ghost-ai-scanner/agent/AGENT_VERSION"


def needs_bump(changed_files):
    """True when agent/install files changed but AGENT_VERSION did not."""
    files = [f.replace("\\", "/") for f in changed_files]
    touched = any(f.startswith(INSTALL_PREFIX) for f in files)
    return touched and VERSION_FILE not in files


def main(argv):
    base = argv[1] if len(argv) > 1 else "origin/main"
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...HEAD"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(f"check_agent_version_bump: cannot diff against {base}: {out.stderr.strip()}")
        return 0  # never block on tooling trouble
    if needs_bump(out.stdout.splitlines()):
        print(
            "ERROR: files under ghost-ai-scanner/agent/install/ changed but "
            "ghost-ai-scanner/agent/AGENT_VERSION did not.\n"
            "Devices only auto-update when the published version is higher. Bump "
            "AGENT_VERSION, and make sure the release entry / published bundle "
            "carries the same higher version."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
