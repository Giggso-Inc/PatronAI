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
# Deliberately does NOT remove Wireshark: the user may have installed it
# themselves or rely on it. Removing a general-purpose tool because we once
# needed it would be a surprise.
# =============================================================

#Requires -RunAsAdministrator

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
