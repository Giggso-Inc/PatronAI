# PatronAI hook-chain library (PowerShell). Loaded from setup and heartbeat.
#
# Git for Windows runs every hook through its bundled sh.exe, so the file at
# .git/hooks/pre-commit MUST be a shell script: a "#!/bin/sh" shim that calls
# PatronAI's PowerShell hook. Never copy pre_commit_hook.ps1 itself into a
# hooks dir - sh then executes PowerShell syntax and every commit fails.

$script:PatronAIChainMarker = "PatronAI managed pre-commit chain"
# First line of pre_commit_hook.ps1. Older installers copied that raw
# PowerShell straight into git-template/hooks/pre-commit, so every repo
# cloned afterwards inherited it (sometimes with another tool's bash block
# appended after it). Used to detect and strip that legacy content.
$script:PatronAIRawHookSignature = "# PatronAI pre-commit hook"

function Get-PatronAIChainBody {
    param([Parameter(Mandatory)][string]$HookScript)
    # Forward slashes: safe inside a double-quoted sh string, and
    # powershell.exe accepts them for -File.
    $ShPath = $HookScript -replace '\\', '/'
    $Lines = @(
        '#!/bin/sh'
        "# $($script:PatronAIChainMarker) - DO NOT EDIT."
        'HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"'
        'if [ -x "$HOOK_DIR/pre-commit.pre-patronai" ]; then'
        '    "$HOOK_DIR/pre-commit.pre-patronai" "$@" || exit $?'
        'fi'
        "powershell -NoProfile -ExecutionPolicy Bypass -File `"$ShPath`""
    )
    return ($Lines -join "`n") + "`n"
}

function Write-PatronAIHookFile {
    # sh needs LF line endings and no UTF-8 BOM in front of "#!".
    # (Set-Content -Encoding UTF8 on Windows PowerShell 5.1 writes a BOM.)
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Body)
    $Body = $Body -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($Path, $Body, (New-Object System.Text.UTF8Encoding($false)))
}

function Remove-PatronAIRawHook {
    # Returns $Content with any inlined legacy pre_commit_hook.ps1 block
    # removed: from the signature line through its final standalone
    # "exit 0" line. Returns "" if nothing but a shebang/blank lines is left.
    param([AllowEmptyString()][string]$Content)
    $Text = ($Content -replace "`r`n", "`n").TrimStart([char]0xFEFF)
    $Pattern = '(?ms)^' + [regex]::Escape($script:PatronAIRawHookSignature) + '[^\n]*\n.*?^exit 0[ \t]*(\n|\z)'
    $Text = [regex]::Replace($Text, $Pattern, '')
    $Meaningful = ($Text -split "`n") | Where-Object { $_.Trim() -and $_ -notmatch '^#!' }
    if (-not $Meaningful) { return "" }
    return $Text
}

function Install-PatronAIChainHook {
    param([Parameter(Mandatory)][string]$HooksDir)

    $HookScript  = Join-Path $env:USERPROFILE ".patronai\pre_commit_hook.ps1"
    $HookPath    = Join-Path $HooksDir "pre-commit"
    $Preserved   = Join-Path $HooksDir "pre-commit.pre-patronai"

    if (-not (Test-Path $HookScript)) { return $false }
    if (-not (Test-Path $HooksDir))   { New-Item -ItemType Directory -Path $HooksDir | Out-Null }

    if (Test-Path $HookPath) {
        try {
            $existing = Get-Content $HookPath -Raw -ErrorAction Stop
        } catch { $existing = "" }
        if ($null -eq $existing) { $existing = "" }
        if ($existing -match $script:PatronAIChainMarker) {
            return $true  # chain already present - idempotent no-op
        }
        # Legacy PatronAI shim from a pre-chain install? Detect by known
        # 2-line signature and drop it - nothing worth preserving.
        $legacy = "#!/bin/sh`npowershell -ExecutionPolicy Bypass -File `"$HookScript`""
        if (($existing -replace "`r","").Trim() -eq ($legacy -replace "`r","")) {
            Remove-Item $HookPath -Force
        } elseif ($existing -match [regex]::Escape($script:PatronAIRawHookSignature)) {
            # Legacy raw-PowerShell hook (from the old git template). Strip
            # PatronAI's block; keep anything another tool (Raven, husky,
            # the user) added around it as the preserved hook.
            $rest = Remove-PatronAIRawHook -Content $existing
            Remove-Item $HookPath -Force
            if ($rest) {
                if ($rest -notmatch '^#!') { $rest = "#!/bin/sh`n" + $rest }
                Write-PatronAIHookFile -Path $Preserved -Body $rest
            }
        } else {
            # Real hook from Raven / husky / user - always preserve it,
            # overwriting any older preserved copy. If husky (or the
            # user) reinstalls its hook after the chain is already in
            # place, the second pass sees the fresh real hook back at
            # $HookPath and MUST keep it - dropping it here would
            # silently strand whatever changed in the reinstall and
            # keep running the stale first-generation preserved copy.
            Move-Item $HookPath $Preserved -Force
        }
    }

    Write-PatronAIHookFile -Path $HookPath -Body (Get-PatronAIChainBody -HookScript $HookScript)
    return $true
}
