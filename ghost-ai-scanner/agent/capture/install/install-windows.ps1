# =============================================================
# FILE: agent/capture/install/install-windows.ps1
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Install the PatronAI capture companion on Windows.
#          Registers TWO scheduled tasks: capture at boot (long-running,
#          SYSTEM) and sync hourly (short-lived).
# =============================================================
# Rendered from a template by the Hub; double-brace values are substituted
# at invite time, same convention as setup_agent.ps1.template.
#
# Delivered as an NSIS .exe built with require_admin=$true, so UAC has already
# been satisfied by the time this runs (installer_bundler.py).
# =============================================================

# MUST be the first statement. Placement-sensitive - see the combined-uninstaller
# ADR in raven-enterprise; it cannot be moved further down the file.
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$Token       = "{{TOKEN}}"
$DeviceId    = "{{DEVICE_ID}}"
$Company     = "{{COMPANY}}"
$UrlsJson    = '{{URLS_JSON}}'          # presigned-URL bundle, single-quoted: raw JSON
$WiresharkUrl    = "{{WIRESHARK_URL}}"  # pinned 4.6.8 installer

$WiresharkVersion = "4.6.8"
$DataDir  = Join-Path $env:ProgramData "PatronAI\capture"
$CodeDir  = Join-Path $DataDir "code"
$Python   = "python"

function Info { param($m) Write-Host "[capture] $m" }
function Ok   { param($m) Write-Host "[capture] + $m" -ForegroundColor Green }
function Die  { param($m) Write-Host "[capture] X $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "PatronAI Capture Companion - Windows"
Write-Host "===================================="
Write-Host ""

# ── 0. Clear any previous install FIRST ──────────────────────────────────
# An install over a live install is the normal case on a real fleet - every
# upgrade is one - and it was completely unhandled until 2026-09-03.
#
# What went wrong: Unregister-ScheduledTask removes the REGISTRATION, not the
# running process. The old service kept running, kept holding capture.log
# open through its own cmd.exe redirect, and the freshly registered task then
# could not open that file for append. cmd reported the failure on the stderr
# it had just failed to redirect, a scheduled task has no console, so it was
# discarded - leaving "LastTaskResult=1" and a completely empty log.
#
# So: stop the tasks, kill the process, stop pktmon, and WAIT for each to
# actually be gone, before touching anything else.
foreach ($t in @("PatronAI Capture", "PatronAI Capture Sync")) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        Info "Stopped existing task: $t"
    }
}

# Get-CimInstance, NOT Get-Process: Get-Process has no CommandLine property on
# PowerShell 5.1, so a -like filter on it silently matches nothing. That exact
# bug in the uninstaller is what let a service survive an uninstall for two
# hours. CommandLine is also $null without rights to the target process, hence
# #Requires -RunAsAdministrator above.
foreach ($proc in @(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -and $_.CommandLine -like "*capture_service*" })) {
    try {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        # Poll: Stop-Process returns before Windows releases the file handles.
        $deadline = (Get-Date).AddSeconds(20)
        while ((Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue) {
            Die "A previous capture_service (PID $($proc.ProcessId)) will not exit. Reboot, then re-run this installer."
        }
        Ok "Stopped a previous capture_service (PID $($proc.ProcessId))"
    } catch {
        Die "Could not stop a previous capture_service (PID $($proc.ProcessId)): $($_.Exception.Message)"
    }
}

# pktmon is a system-wide session, not a child process - killing Python above
# does not stop it, and a leftover session makes the new one fail to start.
$pktmonState = (pktmon status 2>&1 | Out-String)
if ($pktmonState -notmatch "not running|No active") {
    pktmon stop 2>&1 | Out-Null
    Info "Stopped a leftover pktmon capture session"
}

# ── 1. Prerequisites ─────────────────────────────────────────────────────
# Hard-fail rather than install a half-working agent. A capture companion
# that reports healthy while collecting nothing is the failure worth avoiding
# most, so every prerequisite is fatal - none of them warn-and-continue.

# Resolve Python to an ABSOLUTE path. The scheduled tasks run as SYSTEM, and
# SYSTEM's PATH does not include a per-user Python install under
# %LOCALAPPDATA%. Registering the action as the bare name "python" therefore
# produced a task that started, failed to launch, and exited instantly - with
# the installer still reporting success, because this prereq check runs as the
# elevated USER, who does have python on PATH. Checking as the wrong identity
# proved nothing about the one that actually runs the task.
$PythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    Die "Python 3 is required. Install from python.org, then re-run."
}
$Python = $PythonCmd.Source
try { & $Python --version *>$null } catch {
    Die "Python found at $Python but failed to run."
}
Ok "Python found: $Python"

# A per-user Python still works for SYSTEM via an absolute path, but it lives
# inside one user's profile - delete that profile and capture silently stops.
if ($Python -match [regex]::Escape($env:LOCALAPPDATA) -or $Python -match '\\Users\\') {
    Write-Host "[capture] ! Python is a PER-USER install ($Python)." -ForegroundColor Yellow
    Write-Host "[capture] ! Capture runs as SYSTEM and will use this absolute path." -ForegroundColor Yellow
    Write-Host "[capture] ! A machine-wide Python (Program Files) is preferable for fleet use." -ForegroundColor Yellow
}

# pktmon is built into Windows 10 1809+ (build 17763). Nothing to install,
# but an older build genuinely cannot run this.
if ([Environment]::OSVersion.Version.Build -lt 17763) {
    Die "pktmon requires Windows 10 1809 (build 17763) or later. This is build $([Environment]::OSVersion.Version.Build)."
}
if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
    Die "pktmon.exe not found despite a supported Windows build - cannot capture."
}
Ok "pktmon available (built in, no driver install needed)"

# ── 2. Wireshark / tshark, pinned ────────────────────────────────────────
# Pinned because pktmon_to_jsonl.py asks tshark for exact field names, and
# asking for a field family that does not exist returns ZERO ROWS AND EXIT
# CODE 0 - a silent, error-free total loss. capture_service.py re-verifies
# every field at startup regardless; this pin just makes that check pass.
$TsharkExe = Join-Path $env:ProgramFiles "Wireshark\tshark.exe"

if (Test-Path $TsharkExe) {
    $installed = (& $TsharkExe -v 2>$null | Select-Object -First 1)
    if ($installed -match [regex]::Escape($WiresharkVersion)) {
        Ok "tshark $WiresharkVersion already installed"
    } else {
        # Do NOT silently overwrite: installing over a different version
        # downgrades tooling the user may rely on. Their call, not ours.
        Die "A different Wireshark is installed ($installed). Expected $WiresharkVersion. Remove it or install $WiresharkVersion manually, then re-run."
    }
} else {
    Info "Downloading Wireshark $WiresharkVersion..."
    $installer = Join-Path $env:TEMP "Wireshark-$WiresharkVersion-x64.exe"
    Invoke-WebRequest -Uri $WiresharkUrl -OutFile $installer -UseBasicParsing

    # No checksum pin. Removed deliberately 2026-09-03: the pinned hash had to
    # be bumped in lockstep with WIRESHARK_URL, and a URL-only bump turned every
    # install into a "checksum mismatch" that reads like an attack. Integrity of
    # the download now rests on HTTPS to the official Wireshark mirror alone.

    # /S = silent. There is deliberately NO Npcap flag: the Wireshark User's
    # Guide states "the silent installer will not install Npcap" - silent mode
    # never installs it, and there is no switch to pass. Verified empirically
    # too: this repo's dev machine has Wireshark 4.6.8 with no Npcap entry in
    # the uninstall registry, and tshark reads pcapng fine.
    #
    # That suits us exactly: tshark only READS pcapng here (pktmon does the
    # capturing), so we avoid installing a kernel driver AND sidestep the
    # Npcap OEM licensing question.
    #
    # Must be the .exe (NSIS), not the .msi - msiexec does not accept /S.
    Start-Process -FilePath $installer -ArgumentList "/S", "/desktopicon=no" -Wait
    Remove-Item $installer -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $TsharkExe)) { Die "Wireshark install did not produce $TsharkExe" }
    Ok "Wireshark $WiresharkVersion installed"
}

# ── 3. Directories ───────────────────────────────────────────────────────
# Created here; LOCKED DOWN in step 4b, after the files are written.
#
# The lockdown deliberately does NOT happen here. `icacls /inheritance:r /T`
# strips inherited ACEs from existing children, while the (OI)(CI) grant flags
# only govern NEWLY created children - so on a RE-install the previously
# copied .py files were left with no usable DACL and the next Copy-Item failed
# with "Access is denied" even from an elevated prompt. Write first, lock
# afterwards: the first install and every re-install then behave identically.
foreach ($d in @($DataDir, $CodeDir, "$DataDir\keylog", "$DataDir\capture",
                 "$DataDir\spool", "$DataDir\state", "$DataDir\logs")) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
Ok "Created $DataDir"

# ── 4. Companion code + config ───────────────────────────────────────────
# Real files on disk, NOT inlined into this script the way scan_*.py.frag is:
# the parser alone is ~1,400 lines. Integrity is verified against a
# server-side manifest at every startup (common.py); we do not auto-update.
# An EXPLICIT list, never a *.py glob: the source tree also contains dev-only
# harnesses that carry local MinIO credentials, and a glob would ship them to
# the device. This list must match common.py's VERIFIED_FILES, or the startup
# integrity check will refuse to run.
foreach ($f in @("pktmon_to_jsonl.py", "common.py", "capture_service.py", "sync_task.py", "uploader.py")) {
    $src = Join-Path $PSScriptRoot "..\$f"
    if (-not (Test-Path $src)) { Die "Companion file missing from the package: $f" }
    # Remove first: a leftover file from an earlier install may carry a
    # restrictive DACL that -Force alone will not overwrite through.
    $dst = Join-Path $CodeDir $f
    if (Test-Path $dst) { Remove-Item $dst -Force -ErrorAction SilentlyContinue }
    Copy-Item -Path $src -Destination $CodeDir -Force
}
Ok "Installed companion code to $CodeDir"

# Written WITHOUT a BOM. Windows PowerShell 5.1's `Set-Content -Encoding utf8`
# emits EF BB BF, and Python's plain utf-8 decoder rejects it - which made
# urls.json unparseable on the device and surfaced as the misleading
# "no code_manifest_url in urls.json". The companion also reads with
# utf-8-sig now, so this is belt-and-braces; but do not write BOMs into JSON
# that a non-PowerShell process has to read.
$NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    "$DataDir\state\config.json",
    (@{ token = $Token; device_id = $DeviceId; company = $Company } | ConvertTo-Json),
    $NoBom)
[System.IO.File]::WriteAllText("$DataDir\state\urls.json", $UrlsJson, $NoBom)

# Verify what we just wrote actually parses - the failure this replaces was
# invisible until the service refused to start, an install cycle later.
try {
    $probe = Get-Content "$DataDir\state\urls.json" -Raw | ConvertFrom-Json
    if (-not $probe.code_manifest_url) { Die "urls.json is missing code_manifest_url - re-mint the bundle." }
    if (-not $probe.capture_post.url)  { Die "urls.json is missing capture_post.url - re-mint the bundle." }
} catch {
    Die "urls.json did not round-trip as valid JSON: $($_.Exception.Message)"
}
Ok "Wrote config (no BOM, JSON round-trip verified)"

# ── 4b. Lock the tree down ───────────────────────────────────────────────
# The keylog under here is a master key to every TLS session on this machine.
# Anyone who can read it plus a packet capture can decrypt everything, so the
# tree is SYSTEM/Administrators only - inheritance removed, not just narrowed.
#
# Exit code is CHECKED. This was piped to Out-Null before, so a failed lockdown
# would have left the keylog directory world-readable while the installer
# reported success - the exact silent-success failure mode this install has
# already produced twice.
# NO /T. This is the whole bug, and it is subtle:
#   (OI)(CI) are CONTAINER inheritance flags. Applied to a directory they make
#   the ACE propagate to children automatically. But /T walks the tree and
#   applies that same literal ACE to every child INCLUDING FILES, where
#   (OI)(CI) are meaningless - so the grant did not take on the .py files,
#   while /inheritance:r had already stripped their inherited ACEs.
#   Result: files with an EMPTY DACL. Not "restricted" - no access for anyone,
#   including SYSTEM. Python then failed with [Errno 13] Permission denied
#   trying to read its own script, while icacls reported success.
# Without /T, the inheritable ACEs on the directory propagate to children the
# normal way, and files end up with real, working permissions.
icacls $DataDir /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Die "icacls failed (exit $LASTEXITCODE) - refusing to continue with an unprotected keylog directory."
}

# VERIFY the lockdown actually left SYSTEM able to read the code. icacls
# reports "Successfully processed 1 files" even when it produces an empty
# DACL, so its exit code alone proves nothing.
$probe = Join-Path $CodeDir "capture_service.py"
$acl = (icacls $probe) -join " "
if ($acl -notmatch "NT AUTHORITY\\SYSTEM") {
    Die ("Lockdown left $probe unreadable by SYSTEM - the capture task could not start.`n" +
         "          icacls reported: $acl")
}
Ok "Locked down $DataDir (SYSTEM/Administrators only, SYSTEM read verified)"

# ── 5. Scheduled tasks ───────────────────────────────────────────────────
# TWO tasks, deliberately different shapes:
#   capture - at startup, runs forever, NO execution time limit
#   sync    - hourly, short-lived
# The existing scan agent's 2-minute ExecutionTimeLimit would kill capture
# outright, which is why it gets TimeSpan::Zero (unlimited) instead.
#
# ORDER MATTERS, and this used to be wrong: SSLKEYLOGFILE was set BEFORE this
# block, so when Sync registration failed the script aborted having enabled
# machine-wide TLS key logging with no task to consume or clear it. Both
# tasks are now registered first, and either failing unwinds the other, so a
# failed install never leaves key logging switched on.
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Run through cmd.exe so stdout/stderr land in a file. A bare -Execute
# python.exe sends output nowhere on Windows, so a crash before the service
# opens its own log would be undiagnosable.
#
# This redirect is now a BACKSTOP, not the primary log. As of 2026-09-03 the
# services write their log file directly (common.make_logger), because relying
# on this redirect alone made one file handle a single point of failure for
# every diagnostic: an orphaned service holding capture.log made cmd.exe fail
# to open it, and the error went to the stderr it had just failed to redirect.
# Result was "exit 1" with a completely empty log.
#
# NOTE the stream merges into capture.log via 2>&1 - there is no capture.err.
# ABSOLUTE path to cmd.exe. Not strictly required - a bare "cmd.exe" was
# confirmed to resolve fine, so this was NOT the cause of any failure here -
# but naming it explicitly removes one variable, and the bare "python" action
# genuinely did fail to resolve for SYSTEM.
$Cmd = Join-Path $env:SystemRoot "System32\cmd.exe"
if (-not (Test-Path $Cmd)) { Die "cmd.exe not found at $Cmd" }

$CaptureArgs = "/c `"`"$Python`" `"$CodeDir\capture_service.py`" >> `"$DataDir\logs\capture.log`" 2>&1`""
$SyncArgs    = "/c `"`"$Python`" `"$CodeDir\sync_task.py`" >> `"$DataDir\logs\sync.log`" 2>&1`""

try {
    Unregister-ScheduledTask -TaskName "PatronAI Capture" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "PatronAI Capture" -Principal $Principal `
        -Action  (New-ScheduledTaskAction -Execute $Cmd -Argument $CaptureArgs) `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
                                                -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
                                                -DontStopOnIdleEnd -AllowStartIfOnBatteries `
                                                -DontStopIfGoingOnBatteries) | Out-Null
    Ok "Registered 'PatronAI Capture' (at startup, unlimited runtime)"

    # NO -RepetitionDuration. Passing [TimeSpan]::MaxValue here made the
    # ScheduledTasks module emit P99999999DT23H59M59S, which Task Scheduler
    # rejects as out of range (HRESULT 0x80041318) - the cmdlet produced a
    # value its own service refuses.
    #
    # Omitting it registers cleanly AND repeats forever: the resulting XML has
    # no <Duration> inside <Repetition>, which the schema defines as
    # indefinite. Verified by exporting a registered probe task.
    #
    # Do NOT "fix" this by supplying a long finite value such as P3650D. That
    # registers happily and then silently stops syncing years later, with no
    # error anywhere - strictly worse than the crash it replaces.
    Unregister-ScheduledTask -TaskName "PatronAI Capture Sync" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "PatronAI Capture Sync" -Principal $Principal `
        -Action  (New-ScheduledTaskAction -Execute $Cmd -Argument $SyncArgs) `
        -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) `
                    -RepetitionInterval (New-TimeSpan -Hours 1)) `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
                                                -AllowStartIfOnBatteries `
                                                -DontStopIfGoingOnBatteries) | Out-Null
    Ok "Registered 'PatronAI Capture Sync' (hourly, repeats indefinitely)"
} catch {
    Unregister-ScheduledTask -TaskName "PatronAI Capture"      -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "PatronAI Capture Sync" -Confirm:$false -ErrorAction SilentlyContinue
    Die "Could not register the scheduled tasks: $($_.Exception.Message)`n          Rolled both back. SSLKEYLOGFILE was NOT set."
}

# ── 6. SSLKEYLOGFILE, machine-wide ───────────────────────────────────────
# LAST, and deliberately so - this is the only step that changes the
# machine's TLS behaviour, so nothing after it can fail and leave key logging
# on with no consumer.
#
# Read at process LAUNCH only, so already-running processes are not enrolled
# until they restart. Coverage arrives as people restart naturally; the
# prompt below just speeds that up.
$KeyLog = Join-Path $DataDir "keylog\sslkeys.log"
[Environment]::SetEnvironmentVariable("SSLKEYLOGFILE", $KeyLog, "Machine")
Ok "SSLKEYLOGFILE set machine-wide"

Start-ScheduledTask -TaskName "PatronAI Capture"

# VERIFY it actually stayed up. Start-ScheduledTask only reports that the
# scheduler ACCEPTED the start request - a task whose action cannot launch
# (missing interpreter, bad path) reports "started" and dies instantly. That
# exact failure shipped once already; do not trust the start call alone.
Start-Sleep -Seconds 8
$info = Get-ScheduledTaskInfo -TaskName "PatronAI Capture"
$state = (Get-ScheduledTask -TaskName "PatronAI Capture").State
# 267009 = currently running, which is what we want for a long-running task.
if ($state -eq "Running" -or $info.LastTaskResult -eq 267009) {
    Ok "Capture started and still running"
} else {
    Write-Host "[capture] X Capture task is NOT running (state=$state, LastTaskResult=$($info.LastTaskResult))" -ForegroundColor Red
    Write-Host "[capture]   Check: $DataDir\logs\capture.log" -ForegroundColor Red
    # Interpret the ACTUAL code. This previously printed a fixed explanation
    # regardless of the value, which sends the reader after the wrong error.
    switch ($info.LastTaskResult) {
        2 { Write-Host "[capture]   2 = ERROR_FILE_NOT_FOUND - the action executable does not exist." -ForegroundColor Red }
        1 { Write-Host "[capture]   1 = the script ran and exited with an error. The log above is the real cause." -ForegroundColor Red }
        5 { Write-Host "[capture]   5 = ERROR_ACCESS_DENIED - check the ACLs on $CodeDir." -ForegroundColor Red }
        default { Write-Host "[capture]   LastTaskResult $($info.LastTaskResult) - see the log." -ForegroundColor Red }
    }
    Die "Install completed but capture is not running - see above."
}

# ── 7. Browser restart prompt ────────────────────────────────────────────
Write-Host ""
Write-Host "  Browsers and desktop apps already running were started before" -ForegroundColor Yellow
Write-Host "  TLS key logging was enabled, so their traffic cannot be decoded" -ForegroundColor Yellow
Write-Host "  until they restart. Closing and reopening them now gives full"  -ForegroundColor Yellow
Write-Host "  coverage immediately; otherwise it arrives as they restart"     -ForegroundColor Yellow
Write-Host "  naturally over the next day or so."                             -ForegroundColor Yellow
Write-Host ""
Ok "Install complete"
