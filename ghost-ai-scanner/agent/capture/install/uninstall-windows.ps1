# =============================================================
# FILE: agent/capture/install/uninstall-windows.ps1
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Remove the PatronAI capture companion from Windows.
#          Reverses install-windows.ps1 completely.
# =============================================================
# Run with: powershell -ExecutionPolicy Bypass -File uninstall-windows.ps1
# REQUIRES: Administrator rights
#
# By default this does NOT remove Wireshark: the user may have installed it
# themselves or rely on it. Removing a general-purpose tool because we once
# needed it would be a surprise. Pass -RemoveWireshark to opt in - useful for
# rehearsing a clean install, where a pre-existing Wireshark would hide a
# broken download/install step in install-windows.ps1.
#
# NPCAP IS NEVER REMOVED, even with -RemoveWireshark. The Npcap on this box
# belongs to Packetbeat, which bundles and installs its own licensed copy;
# our installer runs Wireshark with /S precisely so it SKIPS Npcap. Removing
# it would break a running Packetbeat that has nothing to do with us.
# =============================================================

#Requires -RunAsAdministrator

param(
    # Opt-in: also uninstall Wireshark, silently, via its own NSIS uninstaller.
    [switch]$RemoveWireshark
)

$ErrorActionPreference = "Continue"   # keep going: a partial install must still clean up

$DataDir = Join-Path $env:ProgramData "PatronAI\capture"

function Info { param($m) Write-Host "[capture] $m" }
function Ok   { param($m) Write-Host "[capture] + $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[capture] ! $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "PatronAI Capture Companion - Uninstall"
Write-Host "======================================"
Write-Host ""

# ── 1. Stop and remove scheduled tasks ───────────────────────────────────
foreach ($task in @("PatronAI Capture", "PatronAI Capture Sync")) {
    $existing = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-ScheduledTask   -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Ok "Removed scheduled task: $task"
    } else {
        Info "Task not present: $task"
    }
}

# ── 2. Stop any capture session still running ────────────────────────────
# pktmon is a system-wide capture session, not a child process - killing the
# Python task does NOT stop it, so it has to be stopped explicitly or it
# keeps writing .etl files forever after the agent is gone.
$pktmonState = (pktmon status 2>&1 | Out-String)
if ($pktmonState -notmatch "not running|No active") {
    pktmon stop 2>&1 | Out-Null
    Ok "Stopped the pktmon capture session"
} else {
    Info "No pktmon session running"
}

Get-Process -Name "python", "pythonw" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*capture_service.py*" } |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue; Ok "Stopped capture_service (PID $($_.Id))" }

# ── 3. Unset SSLKEYLOGFILE ───────────────────────────────────────────────
# The most important step. Left set, every browser launched afterwards keeps
# writing TLS session keys to disk with nothing collecting or clearing them.
$current = [Environment]::GetEnvironmentVariable("SSLKEYLOGFILE", "Machine")
if ($current) {
    [Environment]::SetEnvironmentVariable("SSLKEYLOGFILE", $null, "Machine")
    Ok "Unset SSLKEYLOGFILE (was: $current)"
    Warn "Browsers already running keep writing keys until they restart."
} else {
    Info "SSLKEYLOGFILE was not set"
}

# ── 4. Remove data, keylog first ─────────────────────────────────────────
if (Test-Path $DataDir) {
    # The keylog can decrypt any capture taken while it was collected, so it
    # is shredded first and by name - if the recursive delete below fails
    # partway, this is the one file that must not survive.
    $keylogDir = Join-Path $DataDir "keylog"
    if (Test-Path $keylogDir) {
        Get-ChildItem $keylogDir -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $len = $_.Length
                # Overwrite before unlinking - a plain delete leaves the key
                # material recoverable on disk.
                [System.IO.File]::WriteAllBytes($_.FullName, (New-Object byte[] $len))
            } catch { }
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
        Ok "Shredded TLS keylog files"
    }

    $spool = Join-Path $DataDir "spool"
    if (Test-Path $spool) {
        $pending = @(Get-ChildItem $spool -Filter *.jsonl.gz -ErrorAction SilentlyContinue)
        if ($pending.Count -gt 0) {
            Warn "$($pending.Count) captured batch(es) had NOT been uploaded yet - discarding."
        }
    }

    Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $DataDir) {
        Warn "Could not fully remove $DataDir - a file may still be locked. Reboot and re-run."
    } else {
        Ok "Removed $DataDir"
    }
} else {
    Info "No data directory at $DataDir"
}

Write-Host ""
Ok "Uninstall complete"
Info "Wireshark was NOT removed - remove it yourself if you do not want it."
Write-Host ""

# -- 5. Wireshark (opt-in only) -------------------------------------------
if ($RemoveWireshark) {
    $ws = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
          -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -like 'Wireshark*' } | Select-Object -First 1
    if (-not $ws) {
        Info "Wireshark is not installed - nothing to remove"
    } else {
        $exe = $ws.UninstallString -replace '^"|"$', ''
        Info "Uninstalling $($ws.DisplayName)..."
        try {
            Start-Process -FilePath $exe -ArgumentList '/S' -Wait -ErrorAction Stop
        } catch {
            Warn "Could not launch the Wireshark uninstaller: $($_.Exception.Message)"
        }
        # POLL for the binary, do not trust the exit code. An NSIS uninstaller
        # detaches and returns before the files are unlinked, so checking
        # straight after -Wait reports success while tshark.exe is still there.
        # tshark.exe specifically: it is what the parser actually invokes.
        $deadline = (Get-Date).AddSeconds(90)
        while ((Test-Path "$env:ProgramFiles\Wireshark\tshark.exe") -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
        }
        if (Test-Path "$env:ProgramFiles\Wireshark\tshark.exe") {
            Warn "tshark.exe is still present - remove Wireshark manually via Settings > Apps"
        } else {
            Ok "Wireshark removed (tshark.exe is gone)"
        }
    }
    # State this explicitly: someone rehearsing a clean install would otherwise
    # assume -RemoveWireshark took Npcap with it, and be surprised later.
    Info "Npcap left installed on purpose - it belongs to Packetbeat, not to this companion"
} else {
    Info "Wireshark left installed (pass -RemoveWireshark to remove it too)"
}
