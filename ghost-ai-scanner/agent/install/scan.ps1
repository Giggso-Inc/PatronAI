$AgentDir    = Join-Path $env:USERPROFILE ".patronai"
$ConfigPath  = Join-Path $AgentDir "config.json"
$ScanUrlFile = Join-Path $AgentDir "scan_url.txt"
if (-not (Test-Path $ConfigPath))  { exit 0 }
if (-not (Test-Path $ScanUrlFile)) { exit 0 }
$ScanUrl = (Get-Content $ScanUrlFile).Trim()
if (-not $ScanUrl) { exit 0 }
$Cfg     = Get-Content $ConfigPath | ConvertFrom-Json

# Refresh live authorised list (presigned GET; admin-editable without reinstall).
$AuthUrlFile = Join-Path $AgentDir "authorized_url.txt"
if (Test-Path $AuthUrlFile) {
    $AuthGetUrl = (Get-Content $AuthUrlFile).Trim()
    if ($AuthGetUrl) {
        try {
            $Live = Invoke-WebRequest -Uri $AuthGetUrl -TimeoutSec 10 -UseBasicParsing
            if ($Live.Content) {
                $Live.Content | Set-Content -Path (Join-Path $AgentDir "authorized_domains.txt") -Encoding UTF8
            }
        } catch { <# fallback to local file #> }
    }
}

# Pass token + company into the embedded Python via env so $TOKEN/$COMPANY
# placeholders in scan_header.py.frag bind to the live values.
$env:PATRONAI_TOKEN   = $Cfg.token
$env:PATRONAI_COMPANY = $Cfg.company
$Result = python -c @"
{{INLINE_SCAN_PYTHON}}
"@

if ($Result) {
    try {
        Invoke-WebRequest -Uri $ScanUrl -Method Put -Body $Result `
            -ContentType "application/json" -TimeoutSec 30 | Out-Null
    } catch { <# non-fatal #> }
}
