#!/bin/sh
# Install into Git's effective hook directory, including linked worktrees.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
cd "$REPO_ROOT"

# --git-path honors core.hooksPath and resolves the common Git directory for
# linked worktrees. Never assume that the worktree's .git is a directory.
HOOK_DIR=$(git rev-parse --path-format=absolute --git-path hooks)
[ -n "$HOOK_DIR" ] || { printf 'ERROR: Git returned no hook directory.\n' >&2; exit 1; }
mkdir -p "$HOOK_DIR"
for hook in pre-commit pre-push; do
    cp "$SCRIPT_DIR/git-hooks/$hook" "$HOOK_DIR/$hook"
    chmod +x "$HOOK_DIR/$hook"
    printf 'Installed %s hook -> %s/%s\n' "$hook" "$HOOK_DIR" "$hook"
done
printf 'Pre-commit runs ci_offline_gates.sh --blocking; pre-push runs make verify.\n'
printf 'DCENT_SKIP_VERIFY=1 is a hook-only emergency bypass; release still runs make verify.\n'
