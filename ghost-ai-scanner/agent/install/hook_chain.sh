#!/usr/bin/env bash
# PatronAI hook-chain library. Usage:
#   source "$HOME/.patronai/hook_chain.sh"
#   pa_install_chain_hook "/path/to/.git/hooks"
# Returns 0 if the chain is present after the call, non-zero on error.

pa_install_chain_hook() {
    local hooks_dir="$1"
    local hook_path="$hooks_dir/pre-commit"
    local patronai_hook="$HOME/.patronai/pre_commit_hook.sh"
    local marker="PatronAI managed pre-commit chain"

    [ -x "$patronai_hook" ] || return 1
    mkdir -p "$hooks_dir" || return 1

    if [ -e "$hook_path" ] || [ -L "$hook_path" ]; then
        # Already our chain — nothing to do (idempotent).
        if [ -f "$hook_path" ] && grep -q "$marker" "$hook_path" 2>/dev/null; then
            return 0
        fi
        # Legacy PatronAI symlink from a pre-chain install — replace it.
        if [ -L "$hook_path" ] && [ "$(readlink "$hook_path")" = "$patronai_hook" ]; then
            rm -f "$hook_path"
        else
            # Real hook from Raven / husky / user — always preserve it,
            # overwriting any older preserved copy. If husky (or the
            # user) reinstalls its hook after the chain is already in
            # place, the second pass sees the fresh real hook back at
            # $hook_path and MUST keep it — dropping it here would
            # silently strand whatever changed in the reinstall and
            # keep running the stale first-generation preserved copy.
            local preserved="$hooks_dir/pre-commit.pre-patronai"
            mv "$hook_path" "$preserved" || return 1
            chmod +x "$preserved" 2>/dev/null || true
        fi
    fi

    cat > "$hook_path" << 'CHAIN_HOOK_EOF'
#!/usr/bin/env bash
# PatronAI managed pre-commit chain — DO NOT EDIT.
# Runs the preserved pre-existing hook (if any) first, then PatronAI's
# hook. The preserved hook's exit code aborts the commit on failure;
# PatronAI's hook is fire-and-forget (never blocks a commit).
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -x "$HOOK_DIR/pre-commit.pre-patronai" ]; then
    "$HOOK_DIR/pre-commit.pre-patronai" "$@" || exit $?
fi
"$HOME/.patronai/pre_commit_hook.sh" "$@"
CHAIN_HOOK_EOF
    chmod +x "$hook_path"
    return 0
}
