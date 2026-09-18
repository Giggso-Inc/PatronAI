# PatronAI agent self-update — PowerShell.
#
# Runs hourly via Task Scheduler (PatronAI-Update), separate from the 5-min
# heartbeat that notices an update: doing the file swap inline in heartbeat
# would risk a scheduled heartbeat run reading a half-replaced heartbeat.ps1
# out from under itself. This script only ever touches the generic script
# bodies (heartbeat/scan/hook_chain/pre_commit_hook/diagnose) plus
# agent_version.txt — it never touches config.json, the *_url files, or
# authorized_domains, so the device's identity/enrollment is untouched by
# an update no matter how it turns out.
#
# heartbeat.ps1's own "1. Refresh URLs" step is what writes pending_update.json
# when the backend's urls.json bundle carries a newer version — see that file.
$AgentDir    = Join-Path $env:USERPROFILE ".patronai"
$ConfigPath  = Join-Path $AgentDir "config.json"
$PendingFile = Join-Path $AgentDir "pending_update.json"
$VersionFile = Join-Path $AgentDir "agent_version.txt"
$LockFile    = Join-Path $AgentDir "update.lock"
$AttemptFile = Join-Path $AgentDir "last_update_attempt.json"
$Log         = Join-Path $AgentDir "agent.log"

if (-not (Test-Path $ConfigPath))  { exit 0 }
if (-not (Test-Path $PendingFile)) { exit 0 }

function Write-UpdateLog {
    param([string]$Type, [hashtable]$Extra = @{})
    $Ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    $Line = @{ ts = $Ts; type = $Type }
    foreach ($k in $Extra.Keys) { $Line[$k] = $Extra[$k] }
    ($Line | ConvertTo-Json -Compress) | Add-Content -Path $Log
}

# --- Lock: crash-safety, not multi-machine coordination ----------------------
# A stale lock (>2h old) is from a killed/crashed prior run, not one still in
# progress — this task only ever runs one instance per machine on an hourly
# trigger, so 2h is generous headroom, not a tight race window.
if (Test-Path $LockFile) {
    try {
        $lockInfo = Get-Content $LockFile -Raw | ConvertFrom-Json
        $ageHours = ((Get-Date) - [datetime]$lockInfo.started_at).TotalHours
        if ($ageHours -lt 2) { exit 0 }
    } catch { }
}
@{ pid = $PID; started_at = (Get-Date).ToString("o") } |
    ConvertTo-Json | Set-Content -Path $LockFile -Encoding UTF8

try {
    $Pending = Get-Content $PendingFile -Raw | ConvertFrom-Json
    $TargetVersion = [string]$Pending.latest_agent_version
    $BundleUrl     = [string]$Pending.update_bundle_url
    $BundleSha256  = [string]$Pending.update_bundle_sha256
    if (-not $TargetVersion -or -not $BundleUrl) { exit 0 }

    $CurrentVersion = if (Test-Path $VersionFile) { (Get-Content $VersionFile -Raw).Trim() } else { "" }
    if ($CurrentVersion -eq $TargetVersion) {
        # Already applied (or heartbeat re-wrote the same pending target) —
        # nothing to do. Clear it so this check is cheap next time.
        Remove-Item $PendingFile -Force -ErrorAction SilentlyContinue
        exit 0
    }

    # --- Cooldown: don't retry the same target more than once per 24h --------
    if (Test-Path $AttemptFile) {
        try {
            $last = Get-Content $AttemptFile -Raw | ConvertFrom-Json
            if ($last.target -eq $TargetVersion -and ((Get-Date) - [datetime]$last.at).TotalHours -lt 24) {
                exit 0
            }
        } catch { }
    }

    # --- Fetch ------------------------------------------------------------
    $TmpZip = Join-Path $env:TEMP "patronai-update-$TargetVersion.zip"
    try {
        Invoke-WebRequest -Uri $BundleUrl -OutFile $TmpZip -TimeoutSec 60
    } catch {
        Write-UpdateLog "update_failed" @{ reason = "download_failed"; target = $TargetVersion }
        return
    }

    # --- Validate: checksum, then a well-formed zip --------------------------
    if ($BundleSha256) {
        $actualSha = (Get-FileHash -Path $TmpZip -Algorithm SHA256).Hash.ToLower()
        if ($actualSha -ne $BundleSha256.ToLower()) {
            Write-UpdateLog "update_failed" @{ reason = "checksum_mismatch"; target = $TargetVersion }
            Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
            return
        }
    }

    $ExtractDir = Join-Path $env:TEMP "patronai-update-extract-$TargetVersion"
    if (Test-Path $ExtractDir) { Remove-Item $ExtractDir -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($TmpZip, $ExtractDir)
    } catch {
        Write-UpdateLog "update_failed" @{ reason = "bad_zip"; target = $TargetVersion }
        Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
        return
    }

    $UpdatableFiles = @("heartbeat.ps1", "scan.ps1", "hook_chain.ps1", "pre_commit_hook.ps1", "diagnose.ps1")

    # --- Syntax-check every incoming script BEFORE wiring any of them in ------
    # A corrupt/truncated download that still passes zip validation (e.g. a
    # bundle built from a broken source tree) must not become the file Task
    # Scheduler invokes next.
    $SyntaxOk = $true
    foreach ($f in $UpdatableFiles) {
        $p = Join-Path $ExtractDir $f
        if (Test-Path $p) {
            try {
                $parseErrors = $null
                [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$parseErrors) | Out-Null
                if ($parseErrors -and $parseErrors.Count -gt 0) { $SyntaxOk = $false }
            } catch { $SyntaxOk = $false }
        }
    }
    if (-not $SyntaxOk) {
        Write-UpdateLog "update_failed" @{ reason = "syntax_check_failed"; target = $TargetVersion }
        Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
        Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    # --- Backup: file-level, not a directory swap. config.json/*_url files/
    # authorized_domains/agent.log/first_run.flag/git-template are never
    # touched, so nothing about this device's identity or enrollment can be
    # affected by a bad update or a rollback.
    $BackupDir = Join-Path $AgentDir "_backup_${CurrentVersion}_$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    foreach ($f in ($UpdatableFiles + @("agent_version.txt"))) {
        $src = Join-Path $AgentDir $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $BackupDir $f) -Force }
    }

    # --- Apply --------------------------------------------------------------
    foreach ($f in $UpdatableFiles) {
        $src = Join-Path $ExtractDir $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $AgentDir $f) -Force }
    }
    $TargetVersion | Set-Content -Path $VersionFile -Encoding UTF8

    # --- Smoke-test: run the NEW heartbeat once, check the log line it appends -
    # This is the "confirm the version actually took" step — heartbeat.ps1
    # never calls exit, so it's safe to invoke in-process here.
    & (Join-Path $AgentDir "heartbeat.ps1")
    Start-Sleep -Seconds 2
    $SmokeOk = $false
    try {
        $lastLine = Get-Content $Log -Tail 5 -ErrorAction Stop |
            Where-Object { $_ -match '"type":"heartbeat"' } | Select-Object -Last 1
        if ($lastLine -match '"http_status":(\d+)') {
            $code = [int]$Matches[1]
            $SmokeOk = ($code -ge 200 -and $code -lt 300)
        }
    } catch { }

    if ($SmokeOk) {
        Write-UpdateLog "update_success" @{ from = $CurrentVersion; to = $TargetVersion }
        Remove-Item $PendingFile -Force -ErrorAction SilentlyContinue
        # Prune backups older than 14 days — best-effort, never fails the update.
        try {
            Get-ChildItem -Path $AgentDir -Directory -Filter "_backup_*" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } |
                ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        } catch { }
    } else {
        Write-UpdateLog "update_rolled_back" @{ from = $CurrentVersion; to = $TargetVersion }
        foreach ($f in ($UpdatableFiles + @("agent_version.txt"))) {
            $b = Join-Path $BackupDir $f
            if (Test-Path $b) { Copy-Item $b (Join-Path $AgentDir $f) -Force }
        }
    }

    @{ target = $TargetVersion; at = (Get-Date).ToString("o") } |
        ConvertTo-Json | Set-Content -Path $AttemptFile -Encoding UTF8
    Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
    Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
} finally {
    Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
}
