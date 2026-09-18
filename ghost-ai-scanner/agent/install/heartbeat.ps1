$AgentDir    = Join-Path $env:USERPROFILE ".patronai"
$ConfigPath  = Join-Path $AgentDir "config.json"
$UrlFile     = Join-Path $AgentDir "heartbeat_url.txt"
$RefreshFile = Join-Path $AgentDir "urls_refresh_url.txt"
$Log         = Join-Path $AgentDir "agent.log"
if (-not (Test-Path $ConfigPath)) { exit 0 }
$Cfg = Get-Content $ConfigPath | ConvertFrom-Json

# 1. Refresh URLs from urls.json (best-effort).
if (Test-Path $RefreshFile) {
    $RefreshUrl = (Get-Content $RefreshFile).Trim()
    if ($RefreshUrl) {
        try {
            $Bundle = (Invoke-WebRequest -Uri $RefreshUrl -TimeoutSec 10 -UseBasicParsing).Content | ConvertFrom-Json
            if ($Bundle.heartbeat_put_url)  { $Bundle.heartbeat_put_url  | Set-Content -Path $UrlFile -Encoding UTF8 }
            if ($Bundle.scan_put_url)       { $Bundle.scan_put_url       | Set-Content -Path (Join-Path $AgentDir "scan_url.txt") -Encoding UTF8 }
            if ($Bundle.authorized_get_url) { $Bundle.authorized_get_url | Set-Content -Path (Join-Path $AgentDir "authorized_url.txt") -Encoding UTF8 }
            if ($Bundle.update_available) {
                # apply_update.ps1 (hourly task) picks this up - never applied
                # inline here, so a scheduled apply_update run can never read
                # heartbeat.ps1 half-replaced out from under this very process.
                $Bundle | Select-Object latest_agent_version, update_bundle_url, update_bundle_sha256 |
                    ConvertTo-Json | Set-Content -Path (Join-Path $AgentDir "pending_update.json") -Encoding UTF8
            }
        } catch {
            # urls_refresh_url.txt is itself a presigned URL with the same
            # 7-day TTL and nothing re-pushes a fresh one to this laptop —
            # the 2026-06 fleet heartbeat outage RCA. Fall back to the
            # server's token-authenticated refresh endpoint (no API key).
            try {
                $ServerUrl = "https://patronai.giggso.com/agent/url-refresh/$($Cfg.token)"
                $Bundle = (Invoke-WebRequest -Uri $ServerUrl -TimeoutSec 10 -UseBasicParsing).Content | ConvertFrom-Json
                if ($Bundle.heartbeat_put_url)  { $Bundle.heartbeat_put_url  | Set-Content -Path $UrlFile -Encoding UTF8 }
                if ($Bundle.scan_put_url)       { $Bundle.scan_put_url       | Set-Content -Path (Join-Path $AgentDir "scan_url.txt") -Encoding UTF8 }
                if ($Bundle.authorized_get_url) { $Bundle.authorized_get_url | Set-Content -Path (Join-Path $AgentDir "authorized_url.txt") -Encoding UTF8 }
                if ($Bundle.update_available) {
                    $Bundle | Select-Object latest_agent_version, update_bundle_url, update_bundle_sha256 |
                        ConvertTo-Json | Set-Content -Path (Join-Path $AgentDir "pending_update.json") -Encoding UTF8
                }
            } catch { <# best-effort — retried next cycle #> }
        }
    }
}

# 2. Build identity-rich payload.
if (-not (Test-Path $UrlFile)) { exit 0 }
$HbUrl = (Get-Content $UrlFile).Trim()
if (-not $HbUrl) { exit 0 }
try {
    $Ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
             Select-Object -ExpandProperty IPAddress -Unique)
} catch { $Ips = @() }

# Read from agent_version.txt rather than a literal baked into this script -
# apply_update.ps1 bumps that file in place, so every heartbeat after a
# successful update reports the new version with no change to heartbeat.ps1
# itself.
$AgentVersionFile = Join-Path $AgentDir "agent_version.txt"
$AgentVersionVal = if (Test-Path $AgentVersionFile) { (Get-Content $AgentVersionFile -Raw).Trim() } else { "unknown" }

$Payload = @{
    event_type   = "HEARTBEAT"
    status       = "installed"
    device_id    = $env:COMPUTERNAME
    device_uuid  = $Cfg.device_uuid
    mac_primary  = $Cfg.mac_primary
    ip_set       = $Ips
    email        = $Cfg.email
    token        = $Cfg.token
    company      = $Cfg.company
    os_name      = "Windows"
    os_version   = (Get-CimInstance Win32_OperatingSystem).Version
    agent_version= $AgentVersionVal
    timestamp    = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json -Compress

# 3. PUT, capture HTTP status, append structured log line.
$HttpStatus = 0
try {
    $Resp = Invoke-WebRequest -Uri $HbUrl -Method Put -Body $Payload `
        -ContentType "application/json" -TimeoutSec 30 -UseBasicParsing
    $HttpStatus = [int]$Resp.StatusCode
} catch {
    if ($_.Exception.Response) { $HttpStatus = [int]$_.Exception.Response.StatusCode }
}
$Ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
"{`"ts`":`"$Ts`",`"type`":`"heartbeat`",`"http_status`":$HttpStatus}" | Add-Content -Path $Log

# Step 0.1 — hook coverage backstop. Walk every .git under USERPROFILE
# and ensure the chain-installed pre-commit hook is in place. The
# chain library (hook_chain.ps1) is idempotent: pre-existing Raven /
# husky / user hooks are preserved as pre-commit.pre-patronai and
# called from our chain shim, never overwritten.
$HookScript = Join-Path $AgentDir "pre_commit_hook.ps1"
$ChainLib   = Join-Path $AgentDir "hook_chain.ps1"
if ((Test-Path $HookScript) -and (Test-Path $ChainLib)) {
    . $ChainLib
    $Added  = 0
    $Marker = "PatronAI managed pre-commit chain"
    Get-ChildItem -Path $env:USERPROFILE -Recurse -Depth 4 -Filter ".git" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $HD = Join-Path $_.FullName "hooks"
        $HP = Join-Path $HD "pre-commit"
        # Skip the common case (chain already present) without paying
        # the cost of a rewrite; otherwise defer to the library.
        if ((Test-Path $HP) -and ((Get-Content $HP -Raw -ErrorAction SilentlyContinue) -match $Marker)) {
            return
        }
        if (Install-PatronAIChainHook -HooksDir $HD) { $Added++ }
    }
    if ($Added -gt 0) {
        "{`"ts`":`"$Ts`",`"type`":`"hook_backstop`",`"added`":$Added}" | Add-Content -Path $Log
    }
}
