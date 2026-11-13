r"""Every Invoke-WebRequest must pass -UseBasicParsing.

Without it, PowerShell 5.1 hands the response to the Internet Explorer parsing
engine. On any machine where that engine is unavailable or its first-run
configuration is incomplete -- the norm on Windows 11, where IE is gone -- the
cmdlet raises a ShouldContinue prompt:

    Security Warning: Script Execution Risk
    Invoke-WebRequest parses the content of the web page. Script code in the
    web page might be run when the page is parsed.
      RECOMMENDED ACTION: Use the -UseBasicParsing switch ...
    [Y] Yes  [A] Yes to All  [N] No  [L] No to All ... (default is "N")

Two different failures follow, and both were live:

1. Interactive (the installer). A real user hit this on 2026-11-13 at the
   install-status PUT and happened to type Y. The default is **N**, and that
   branch's catch is `<# non-fatal #>`, so anyone who pressed Enter installed
   successfully while the Hub never learned the install completed. At the OTP
   meta download the same prompt is worse: declining reports "Cannot reach
   installation server. URL may have expired." -- which is false, and sends
   people chasing a network problem that does not exist.

2. Non-interactive (the scheduled tasks). There is no prompt to answer.
   PowerShell throws

       Windows PowerShell is in NonInteractive mode.
       Read and Prompt functionality is not available.

   Verified empirically on Windows 11 (PS 5.1.26100) against a local server:
   WITHOUT the switch both an HTML and a JSON response fail this way; WITH it
   both return 200. The response content type is irrelevant -- the prompt is
   attempted before the body is looked at.

   That means PatronAI-Scan (every 30 min) and PatronAI-Update (every 60 min)
   fail on every cycle on an affected machine. scan.ps1's catch is
   `<# non-fatal #>`, so scan results were being dropped in total silence, and
   the agent could not self-update to a build that fixed it.

A static guard, not a runtime test: it is the shape of the call that is wrong,
and it costs nothing to check on every commit.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# A call starts at `Invoke-WebRequest` and continues across backtick line
# continuations, so the switch may legitimately sit several lines below the
# cmdlet name. Grepping a single line reports false positives -- that mistake
# was made while diagnosing this very bug.
CMDLET = re.compile(r"\bInvoke-WebRequest\b")


def _powershell_files() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for pattern in ("**/*.ps1", "**/*.ps1.template", "**/*.psm1"):
        out.extend(p for p in ROOT.glob(pattern) if ".git" not in p.parts)
    return sorted(set(out))


def _call_text(lines: list[str], start: int) -> tuple[str, int]:
    """Return the full invocation beginning at `start`, following backticks."""
    collected = [lines[start]]
    i = start
    while lines[i].rstrip().endswith("`") and i + 1 < len(lines):
        i += 1
        collected.append(lines[i])
    return "\n".join(collected), i


def _offenders() -> list[tuple[str, int, str]]:
    bad: list[tuple[str, int, str]] = []
    for path in _powershell_files():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if CMDLET.search(line) and not line.strip().startswith("#"):
                call, end = _call_text(lines, i)
                if "-UseBasicParsing" not in call:
                    rel = path.relative_to(ROOT).as_posix()
                    bad.append((rel, i + 1, call.strip().splitlines()[0]))
                i = end + 1
                continue
            i += 1
    return bad


def test_every_invoke_webrequest_uses_basic_parsing() -> None:
    offenders = _offenders()
    detail = "".join("\n  %s:%d  %s" % o for o in offenders)
    assert not offenders, (
        "Invoke-WebRequest without -UseBasicParsing prompts on any machine "
        "without a usable Internet Explorer engine, and THROWS outright in a "
        "non-interactive host such as a scheduled task:" + detail
    )


def test_the_four_sites_that_were_broken_stay_fixed() -> None:
    """Pinned by name, so a refactor cannot quietly drop one back."""
    expected = {
        "ghost-ai-scanner/agent/install/setup_agent.ps1.template": 2,
        "ghost-ai-scanner/agent/install/apply_update.ps1": 1,
        "ghost-ai-scanner/agent/install/scan.ps1": 1,
    }
    for rel, count in expected.items():
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        assert text.count("-UseBasicParsing") >= count, (
            "%s should carry at least %d -UseBasicParsing switches" % (rel, count)
        )
