# =============================================================
# FILE: run_dev_minio.ps1
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc
# PURPOSE: Start the patron_v2 Streamlit dashboard against local MinIO.
#          Canonical entry point - loads .env and resolves the venv itself,
#          so there is no env var to hand-copy or forget.
# USAGE: powershell -File run_dev_minio.ps1
# =============================================================
# Reuses the venv at patron/PatronAI/ghost-ai-scanner/.venv (STARTUP.md 3).
# It already has streamlit, polars, boto3, bcrypt - no second install.
#
# Port 8503, NOT 8501/8502: STARTUP.md records 8501 as DLP's and 8502 as the
# legacy PatronAI UI. This is a third, parallel instance.
# =============================================================

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Here))) `
                  "PatronAI\ghost-ai-scanner\.venv\Scripts\python.exe"

function Info { param($m) Write-Host "[patron_v2] $m" }
function Ok   { param($m) Write-Host "[patron_v2] + $m" -ForegroundColor Green }
function Die  { param($m) Write-Host "[patron_v2] X $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "PatronAI v2 - dev against MinIO"
Write-Host "==============================="
Write-Host ""

if (-not (Test-Path $Venv)) {
    Die "venv not found at $Venv`n          Create it per STARTUP.md section 3, or point `$Venv at another one."
}
Ok "venv: $Venv"

# ── Load .env ────────────────────────────────────────────────────────────
# Set into the CURRENT process only. Deliberately not -Scope Machine: this is
# a dev instance and must not alter anything else on the box.
$EnvFile = Join-Path $Here ".env"
if (-not (Test-Path $EnvFile)) { Die "No .env at $EnvFile" }
Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^\s*#' -or $_ -notmatch '=') { return }
    $k, $v = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim(), "Process")
}
Ok ".env loaded (STORAGE_MODE=$env:STORAGE_MODE, bucket=$env:PATRONAI_BUCKET)"

# ── MinIO must be up ─────────────────────────────────────────────────────
# Checked BEFORE launching: Streamlit would otherwise start fine and every
# panel would fail one by one, which reads as an app bug rather than a
# missing container.
try {
    $null = Invoke-WebRequest -Uri "$env:LOCAL_STORAGE_ENDPOINT/minio/health/live" `
                              -TimeoutSec 4 -UseBasicParsing
    Ok "MinIO reachable at $env:LOCAL_STORAGE_ENDPOINT"
} catch {
    Die ("MinIO not reachable at $env:LOCAL_STORAGE_ENDPOINT`n" +
         "          Start it:  docker compose --profile minio up -d")
}

# ── Prove the backend works before the UI depends on it ──────────────────
Info "Verifying storage..."
& $Venv (Join-Path $Here "scripts\verify_storage.py") --bucket $env:PATRONAI_BUCKET
if ($LASTEXITCODE -ne 0) { Die "Storage verification failed - see above." }

# ── Launch ───────────────────────────────────────────────────────────────
$Port = if ($env:STREAMLIT_PORT) { $env:STREAMLIT_PORT } else { "8503" }
Write-Host ""
Ok "Starting Streamlit on http://127.0.0.1:$Port"
Info "Network tab: sidebar -> Network   (admin/support roles)"
Write-Host ""

Push-Location $Here
try {
    # PYTHONPATH so `import store...` / `import ui...` resolve the way
    # main.py and Streamlit set them up. SEMICOLONS - Windows' path separator;
    # a colon here silently yields one unusable path and every import fails.
    $env:PYTHONPATH = "$Here\src;$Here\dashboard;$Here"
    & $Venv -m streamlit run (Join-Path $Here "dashboard\ghost_dashboard.py") `
        --server.port $Port --server.address 127.0.0.1 `
        --server.headless true --browser.gatherUsageStats false
} finally {
    Pop-Location
}
