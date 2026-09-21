# PatronAI pre-commit hook — PowerShell
$ConfigPath = Join-Path $env:USERPROFILE ".patronai\config.json"
if (-not (Test-Path $ConfigPath)) { exit 0 }
$Cfg    = Get-Content $ConfigPath | ConvertFrom-Json
$Bucket = $Cfg.bucket; $Region = $Cfg.region; $Company = $Cfg.company
if (-not $Bucket) { exit 0 }
$Diff = git diff --cached --unified=3 2>$null
if (-not $Diff) { exit 0 }
$Signals = "langchain|llama_index|autogen|crewai|openai\.agents|MCPServer|api\.openai\.com|sk-proj-|sk-ant-"
if (-not ($Diff -match $Signals)) { exit 0 }
$DeviceId  = $env:COMPUTERNAME
$Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
$Repo      = Split-Path -Leaf (git rev-parse --show-toplevel 2>$null)
$Branch    = git rev-parse --abbrev-ref HEAD 2>$null
$Snippet   = $Diff.Substring(0, [Math]::Min($Diff.Length, 5120))
$Payload   = @{event_type="GIT_DIFF_SIGNAL";source="patronai_git_hook_ps";
               device_id=$DeviceId;company=$Company;repo=$Repo;branch=$Branch;
               timestamp=$Timestamp;diff_snippet=$Snippet} | ConvertTo-Json -Compress
$Key = "ocsf/agent/git-diffs/$DeviceId-$Timestamp.json"
aws s3 cp - "s3://$Bucket/$Key" --region $Region --content-type "application/json" --quiet 2>$null
exit 0
