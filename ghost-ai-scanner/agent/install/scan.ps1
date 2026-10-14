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

# `python -c "<script>"` passes the ENTIRE script as one command-line
# argument. The combined scan_*.py.frag payload is 50+ KB and grows with
# every new emitter added - Windows' CreateProcess command-line length
# limit is exceeded long before that, failing with "Program 'python.exe'
# failed to run: The filename or extension is too long" and silently
# producing no scan output at all (caught here, but scan.ps1 has no
# logging of its own, so this failed completely invisibly - confirmed
# live: heartbeats were landing in S3 every 5 min while scans/ stayed
# empty). Writing to a temp .py file and invoking `python <path>` instead
# keeps the command line to just a short file path, with no size limit on
# the script itself.
$PyScript = Join-Path $env:TEMP ("patronai_scan_" + [guid]::NewGuid().ToString("N") + ".py")
@"
{{INLINE_SCAN_PYTHON}}
"@ | Set-Content -Path $PyScript -Encoding UTF8
$Result = python $PyScript
Remove-Item $PyScript -Force -ErrorAction SilentlyContinue

if ($Result) {
    try {
        Invoke-WebRequest -Uri $ScanUrl -Method Put -Body $Result `
            -ContentType "application/json" -TimeoutSec 30 | Out-Null
    } catch { <# non-fatal #> }
}
