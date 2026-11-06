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
                $Live.Content | Set-Content -Path (Join-Path $AgentDir "authorized_domains") -Encoding UTF8
            }
        } catch { <# fallback to local file #> }
    }
}

# Pass token + company into the embedded Python via env so scan_header.py.frag
# reads the live values from the environment (not substituted at render time).
$env:PATRONAI_TOKEN   = $Cfg.token
$env:PATRONAI_COMPANY = $Cfg.company

# Write the inlined Python to a temp file and run it as a script file.
# Using 'python -c @"..."@' silently produces no output on Windows because the
# inlined scan code (~53 KB) exceeds Windows' 32,767-char CreateProcess
# command-line limit — the process never starts and $Result stays empty.
# Writing to a file has no such limit and mirrors the Linux heredoc approach.
$PyTmp = Join-Path $env:TEMP "patronai_scan.py"
$Result = ""
try {
    @'
{{INLINE_SCAN_PYTHON}}
'@ | Set-Content -Path $PyTmp -Encoding UTF8
    $Result = python $PyTmp 2>$null
} finally {
    Remove-Item -Path $PyTmp -Force -ErrorAction SilentlyContinue
}

if ($Result) {
    try {
        Invoke-WebRequest -Uri $ScanUrl -Method Put -Body $Result `
            -ContentType "application/json" -TimeoutSec 30 | Out-Null
    } catch { <# non-fatal #> }
}
