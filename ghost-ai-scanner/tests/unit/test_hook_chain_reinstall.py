# =============================================================
# FILE: tests/unit/test_hook_chain_reinstall.py
# VERSION: 1.0.0
# UPDATED: 2026-07-24
# OWNER: Giggso Inc
# PURPOSE: Regression guard for the chain-install "second conflict"
#          case Codex flagged on PR#15. If husky (or the user, or a
#          package upgrade) reinstalls its own pre-commit hook AFTER
#          PatronAI's chain is already in place, the next chain-
#          install pass MUST preserve the fresh real hook, not
#          silently discard it and keep running the stale first-
#          generation preserved copy. Exercises the actual
#          pa_install_chain_hook shell function extracted from
#          setup_agent.sh.template — a template drift will fail
#          this test rather than silently regress the fix.
# =============================================================

import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATE = _ROOT / "agent" / "install" / "setup_agent.sh.template"


def _extract_chain_library(template_text: str) -> str:
    """Pull the hook_chain.sh library body out of the setup template.

    The template emits it via `cat > "$HOOK_CHAIN_LIB" << 'CHAIN_LIB_EOF'
    ... CHAIN_LIB_EOF`. That inner content is the library we want to
    exercise standalone. Match strictly to catch template drift."""
    m = re.search(
        r"<<\s*'CHAIN_LIB_EOF'\s*\n(?P<body>.*?)^CHAIN_LIB_EOF\s*$",
        template_text,
        re.DOTALL | re.MULTILINE,
    )
    if not m:
        raise RuntimeError(
            "Could not locate the CHAIN_LIB_EOF heredoc in setup_agent.sh.template — "
            "template drift may have broken the hook-chain regression harness."
        )
    return m.group("body")


@pytest.fixture(scope="module")
def chain_lib_text() -> str:
    return _extract_chain_library(_TEMPLATE.read_text(encoding="utf-8"))


def _run_bash(script: str) -> subprocess.CompletedProcess:
    """Run a bash snippet with `set -u` disabled (the library uses
    ${VAR:-default} guards, but the harness intentionally leaves other
    vars unset). stderr is captured for assertion messages."""
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        capture_output=True, text=True, timeout=15,
    )


def test_second_conflict_preserves_fresh_hook_not_stale(chain_lib_text, tmp_path):
    """The scenario Codex called out:

      1. Repo has husky's hook A. PatronAI chain-installs — moves A to
         pre-commit.pre-patronai, writes chain script at pre-commit.
      2. Husky reinstalls hook B, overwriting the chain script.
      3. Heartbeat backstop runs pa_install_chain_hook again. It must
         preserve B (the new real hook) at pre-commit.pre-patronai and
         rewrite the chain script — NOT delete B and keep A around as
         the stale preserved copy.
    """
    lib_path       = tmp_path / "hook_chain.sh"
    lib_path.write_text(chain_lib_text)
    hooks_dir      = tmp_path / "hooks"
    hooks_dir.mkdir()
    patronai_hook  = tmp_path / "patronai_hook.sh"
    patronai_hook.write_text("#!/usr/bin/env bash\necho patronai-hook-ran\n")
    patronai_hook.chmod(0o755)

    # Simulate hook A (husky v1) already present.
    (hooks_dir / "pre-commit").write_text("#!/usr/bin/env bash\necho husky-A\n")
    (hooks_dir / "pre-commit").chmod(0o755)

    script = textwrap.dedent(f"""
        # The chain library references $HOME/.patronai/pre_commit_hook.sh;
        # override HOME so it resolves to our fake patronai_hook.sh.
        export HOME={tmp_path}
        mkdir -p "$HOME/.patronai"
        cp {patronai_hook} "$HOME/.patronai/pre_commit_hook.sh"
        chmod +x "$HOME/.patronai/pre_commit_hook.sh"
        source {lib_path}

        # Pass 1: chain-install with husky A in place.
        pa_install_chain_hook {hooks_dir}
        # husky-A should now be the preserved copy.
        grep -q "husky-A" {hooks_dir}/pre-commit.pre-patronai || {{ echo "FAIL: husky-A not preserved after pass 1" >&2; exit 1; }}
        # Chain script should be at pre-commit.
        grep -q "PatronAI managed pre-commit chain" {hooks_dir}/pre-commit || {{ echo "FAIL: chain not installed after pass 1" >&2; exit 1; }}

        # Simulate husky reinstalling itself: overwrite our chain with husky B.
        cat > {hooks_dir}/pre-commit <<'EOF'
#!/usr/bin/env bash
echo husky-B
EOF
        chmod +x {hooks_dir}/pre-commit

        # Pass 2 (heartbeat backstop). The bug this test guards against
        # is: pa_install_chain_hook sees preserved already exists, deletes
        # husky B, and keeps stale husky A as the "preserved" hook. The
        # fix is: always overwrite preserved with the CURRENT hook.
        pa_install_chain_hook {hooks_dir}
        # The preserved copy MUST now be husky B (the fresh reinstall),
        # NOT husky A (the stale first-generation preservation).
        grep -q "husky-B" {hooks_dir}/pre-commit.pre-patronai || {{ echo "FAIL: preserved is stale (still husky-A)" >&2; exit 1; }}
        grep -q "husky-A" {hooks_dir}/pre-commit.pre-patronai && {{ echo "FAIL: preserved still contains husky-A after pass 2" >&2; exit 1; }}
        # Chain script must be back in place (this half was never broken,
        # but assert it so a wholesale regression trips this test too).
        grep -q "PatronAI managed pre-commit chain" {hooks_dir}/pre-commit || {{ echo "FAIL: chain not restored after pass 2" >&2; exit 1; }}
        echo OK
    """).strip()

    result = _run_bash(script)
    assert result.returncode == 0, (
        f"hook-chain second-conflict regression FAILED.\n"
        f"stderr:\n{result.stderr}\nstdout:\n{result.stdout}"
    )
    assert "OK" in result.stdout


def test_idempotent_when_chain_already_present(chain_lib_text, tmp_path):
    """pa_install_chain_hook is called by the 5-min heartbeat backstop —
    if the chain is already there, it must be a no-op (no clobbering,
    no rewrites, no duplicate preservation)."""
    lib_path      = tmp_path / "hook_chain.sh"
    lib_path.write_text(chain_lib_text)
    hooks_dir     = tmp_path / "hooks"
    hooks_dir.mkdir()

    script = textwrap.dedent(f"""
        export HOME={tmp_path}
        mkdir -p "$HOME/.patronai"
        cat > "$HOME/.patronai/pre_commit_hook.sh" <<'EOF'
#!/usr/bin/env bash
echo patronai-ok
EOF
        chmod +x "$HOME/.patronai/pre_commit_hook.sh"
        source {lib_path}

        # Real hook exists — first pass preserves it, installs chain.
        cat > {hooks_dir}/pre-commit <<'EOF'
#!/usr/bin/env bash
echo real-hook
EOF
        chmod +x {hooks_dir}/pre-commit
        pa_install_chain_hook {hooks_dir}

        # Snapshot the state.
        chain_before=$(cat {hooks_dir}/pre-commit)
        preserved_before=$(cat {hooks_dir}/pre-commit.pre-patronai)

        # Second pass with chain already in place — should be a no-op.
        pa_install_chain_hook {hooks_dir}

        chain_after=$(cat {hooks_dir}/pre-commit)
        preserved_after=$(cat {hooks_dir}/pre-commit.pre-patronai)

        [ "$chain_before" = "$chain_after" ]         || {{ echo "FAIL: chain rewritten on idempotent pass" >&2; exit 1; }}
        [ "$preserved_before" = "$preserved_after" ] || {{ echo "FAIL: preserved rewritten on idempotent pass" >&2; exit 1; }}
        # And no duplicate preserved files.
        [ ! -e {hooks_dir}/pre-commit.pre-patronai.1 ] || {{ echo "FAIL: duplicate preserved file created" >&2; exit 1; }}
        echo OK
    """).strip()

    result = _run_bash(script)
    assert result.returncode == 0, (
        f"idempotent-second-pass FAILED.\nstderr:\n{result.stderr}\nstdout:\n{result.stdout}"
    )
    assert "OK" in result.stdout
