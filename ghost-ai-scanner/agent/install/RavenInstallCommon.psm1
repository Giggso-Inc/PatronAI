#Requires -Version 5.1
# ==============================================================================
# RavenInstallCommon -- shared preflight/runtime helpers for every Windows
# installer entry point (Raven agent, Raven org-invite template, Raven
# add-on template, CoworkDLP, PatronAI agent template).
#
# Phase 1 of the installer-architecture proposal (2026-11-17): these
# functions already existed, duplicated and drifting, across 5 separate
# files. This module is the single copy; each entry point now imports it
# instead of carrying its own version. ZERO behavior change versus the
# best existing version of each function -- the VC++ detection below is
# copied verbatim from hub/templates/raven_install.ps1.template (PR #657),
# not reimplemented.
#
# Import from any entry point with:
#   Import-Module (Join-Path $PSScriptRoot "RavenInstallCommon.psm1") -Force
#
# This module must be imported, and Assert-RavenRelaunched64Bit called,
# BEFORE any installer-specific logic runs (OTP collection, self-enroll,
# feature installs). It changes nothing about what happens after that --
# it only guarantees WHICH PowerShell host runs it.
# ==============================================================================

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------
# Change 2 -- Runtime pin: relaunch as 64-bit PowerShell before anything
# else runs, instead of detecting-and-working-around 32-bit/WOW64 issues
# at each individual call site.
#
# [2026-11-17] Root cause this closes: raven_install.ps1.template's own
# comment admits it relaunches NOTHING -- only install-windows.ps1 (the
# agent step) self-relaunches. The template's VC++ check was fixed to read
# correctly THROUGH Sysnative under 32-bit PowerShell (PR #657), but
# every other 32-bit-sensitive read in that same file ($env:ProgramFiles,
# $env:PROCESSOR_ARCHITECTURE) was never fixed, because the script never
# stops being 32-bit in the first place. This function removes the cause
# instead of adding a third individually-patched call site.
#
# Safe to call from a script that is ALREADY 64-bit: Is64BitProcess is
# true, the condition below is false, and the function returns immediately
# with no relaunch, no extra process, no behavior change.
# ------------------------------------------------------------------------
function Assert-RavenRelaunched64Bit {
    param(
        # Pass $PSCommandPath from the CALLING script -- this module has no
        # reliable path of its own once imported/inlined, and relaunching
        # the wrong file would be worse than not relaunching at all.
        #
        # [2026-11-17] NOT Mandatory, and deliberately typed to allow an
        # empty string -- found by actually RUNNING this function (not just
        # syntax-checking it): $PSCommandPath is empty in some invocation
        # contexts (e.g. pasted into an interactive session rather than run
        # as a real .ps1 file), and a Mandatory parameter rejects an empty
        # string at BIND time, before the function body's own
        # "-and $ScriptPath" fallback check ever gets a chance to run. The
        # real shipped installers always run as a real file
        # (powershell -File ...), where $PSCommandPath is always populated
        # -- this only matters for robustness in atypical invocations.
        [AllowEmptyString()][string]$ScriptPath = "",
        [string[]]$ScriptArgs = @()
    )

    # Matches the proven pattern already shipping in
    # hub/app/assets/addon_scripts/windows.ps1 (2026-11-12) exactly,
    # including the env-var relaunch guard -- that script's own comment
    # notes this is the SAME architecture-normalization problem as
    # raven_install.ps1.template, just fixed correctly in this one place
    # first. Extracted here so both (and every other entry point) share
    # one copy instead of three independently-drifting ones.
    #
    # The guard (RAVEN_ORG_ARCH_RELAUNCHED) is defensive: Is64BitProcess
    # should always be true immediately after a real relaunch, so the
    # condition below is false on the second pass regardless -- but an
    # environment-variable belt-and-braces costs nothing and this is
    # exactly the kind of check a stale/weird PowerShell host is the type
    # to get wrong in a way nobody has seen yet.
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess `
            -and -not $env:RAVEN_ORG_ARCH_RELAUNCHED -and $ScriptPath) {
        $sysNativePwsh = Join-Path $env:SystemRoot "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
        if (Test-Path $sysNativePwsh) {
            Write-Host "  32-bit PowerShell on 64-bit Windows -- restarting this installer in 64-bit PowerShell..." -ForegroundColor DarkCyan
            $env:RAVEN_ORG_ARCH_RELAUNCHED = "1"
            & $sysNativePwsh -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @ScriptArgs
            exit $LASTEXITCODE
        }
        Write-Host "  32-bit PowerShell on 64-bit Windows and sysnative is unavailable -- using architecture-aware fallbacks." -ForegroundColor DarkYellow
    }
}

# ------------------------------------------------------------------------
# VC++ runtime detection -- copied verbatim from
# hub/templates/raven_install.ps1.template (PR #657). Do not re-derive;
# this exact version already fixed two real, confirmed bugs (WOW64
# redirection via Sysnative, and false negatives from gating on
# vcruntime140*.dll which CPython vendors itself). CoworkDLP's
# check_prerequisites.ps1 still has the OLD, disproven 3-DLL/System32
# version -- importing this module into that file is exactly what fixes it.
# ------------------------------------------------------------------------
function Get-VCRedistState {
    $sysDir = Join-Path $env:SystemRoot "System32"
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        $sysDir = Join-Path $env:SystemRoot "Sysnative"
    }

    $regVersion = $null
    $regInstalled = $false
    try {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $key = $hklm.OpenSubKey("SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64")
        if ($key) {
            $regInstalled = ([int]$key.GetValue("Installed", 0) -eq 1)
            $regVersion = [string]$key.GetValue("Version", "")
            $key.Close()
        }
        $hklm.Close()
    } catch { }

    [pscustomobject]@{
        SystemDir  = $sysDir
        Msvcp140   = Test-Path (Join-Path $sysDir "msvcp140.dll")
        RegInstall = $regInstalled
        RegVersion = $regVersion
    }
}

function Test-VCRedistPresent {
    $st = Get-VCRedistState
    return [bool]$st.Msvcp140
}

# ------------------------------------------------------------------------
# Web calls -- every outbound request wrapped with -UseBasicParsing by
# construction, so the IE-engine ShouldContinue prompt (interactive,
# defaults to declining) and the NonInteractive-mode throw (scheduled
# tasks) become structurally impossible here, instead of relying on every
# call site remembering the switch by hand -- the exact omission PatronAI
# fixed 4 times over in PR #88.
# ------------------------------------------------------------------------
function Invoke-RavenWebRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Method = "GET",
        [string]$Body = $null,
        [hashtable]$Headers = @{},
        [int]$TimeoutSec = 30,
        [string]$OutFile = $null
    )
    $params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
    }
    if ($Body) { $params["Body"] = $Body; $params["ContentType"] = "application/json" }
    if ($OutFile) { $params["OutFile"] = $OutFile }
    return Invoke-WebRequest @params
}

# ------------------------------------------------------------------------
# BOM-less UTF-8 file writes -- Set-Content -Encoding utf8 on PowerShell
# 5.1 emits a UTF-8 BOM, which every Python reader of a generated config
# (sync.py, slm_onnx.py, guardrail_classifier.py in CoworkDLP) fails to
# parse with JSONDecodeError. WriteAllText with an explicit BOM-less
# encoding matches what every consumer actually expects.
# ------------------------------------------------------------------------
function Write-RavenFileNoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding $false))
}

# ------------------------------------------------------------------------
# Start-Process wrapper that always captures -PassThru and returns a real
# exit code -- the exact mechanism the WOW64 incident's own postmortem
# named as the reason the real failure produced no diagnostic at all.
#
# -Wait is OPTIONAL, not defaulted to $true, because at least one real
# caller needs fire-and-forget launch semantics (PatronAI's background
# first-scan trigger) -- defaulting it here would silently turn that into
# a blocking call. Caller contract: if -Wait is omitted, the returned
# process object's .ExitCode is NOT meaningful (the process has not
# necessarily terminated yet) -- it still proves the launch itself
# succeeded (PassThru always set), which is the signal fire-and-forget
# callers actually want. Callers that need the real exit code MUST pass
# -Wait.
# ------------------------------------------------------------------------
function Start-RavenProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$Wait,
        [switch]$NoNewWindow
    )
    $params = @{ FilePath = $FilePath; ArgumentList = $ArgumentList; PassThru = $true }
    if ($Wait) { $params["Wait"] = $true }
    if ($NoNewWindow) { $params["NoNewWindow"] = $true }
    $proc = Start-Process @params
    return $proc  # caller reads $proc.ExitCode -- never silently discarded.
}

Export-ModuleMember -Function `
    Assert-RavenRelaunched64Bit, `
    Get-VCRedistState, `
    Test-VCRedistPresent, `
    Invoke-RavenWebRequest, `
    Write-RavenFileNoBom, `
    Start-RavenProcess
