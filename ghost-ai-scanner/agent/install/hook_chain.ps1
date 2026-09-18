# PatronAI hook-chain library (PowerShell). Loaded from setup and heartbeat.
function Install-PatronAIChainHook {
    param([Parameter(Mandatory)][string]$HooksDir)

    $HookScript  = Join-Path $env:USERPROFILE ".patronai\pre_commit_hook.ps1"
    $HookPath    = Join-Path $HooksDir "pre-commit"
    $Preserved   = Join-Path $HooksDir "pre-commit.pre-patronai"
    $Marker      = "PatronAI managed pre-commit chain"

    if (-not (Test-Path $HookScript)) { return $false }
    if (-not (Test-Path $HooksDir))   { New-Item -ItemType Directory -Path $HooksDir | Out-Null }

    if (Test-Path $HookPath) {
        try {
            $existing = Get-Content $HookPath -Raw -ErrorAction Stop
        } catch { $existing = "" }
        if ($existing -match $Marker) {
            return $true  # chain already present — idempotent no-op
        }
        # Legacy PatronAI shim from a pre-chain install? Detect by known
        # 2-line signature and drop it — nothing worth preserving.
        $legacy = "#!/bin/sh`npowershell -ExecutionPolicy Bypass -File `"$HookScript`""
        if (($existing -replace "`r","") -eq ($legacy -replace "`r","")) {
            Remove-Item $HookPath -Force
        } else {
            # Real hook from Raven / husky / user — always preserve it,
            # overwriting any older preserved copy. If husky (or the
            # user) reinstalls its hook after the chain is already in
            # place, the second pass sees the fresh real hook back at
            # $HookPath and MUST keep it — dropping it here would
            # silently strand whatever changed in the reinstall and
            # keep running the stale first-generation preserved copy.
            Move-Item $HookPath $Preserved -Force
        }
    }

    $ChainBody = @"
#!/bin/sh
# PatronAI managed pre-commit chain — DO NOT EDIT.
HOOK_DIR="`$(cd "`$(dirname "`$0")" && pwd)"
if [ -x "`$HOOK_DIR/pre-commit.pre-patronai" ]; then
    "`$HOOK_DIR/pre-commit.pre-patronai" "`$@" || exit `$?
fi
powershell -ExecutionPolicy Bypass -File "$HookScript"
"@
    $ChainBody | Set-Content -Path $HookPath -Encoding UTF8
    return $true
}
