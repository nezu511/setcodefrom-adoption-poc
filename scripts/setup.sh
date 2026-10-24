#!/usr/bin/env bash
# Build the two execution-specs trees of this PoC at pinned commits.
#
#   scripts/setup.sh <work-dir> [--use-patch]
#
# Creates, inside <work-dir> (which may already exist):
#   execution-specs/  a blobless clone of ethereum/execution-specs
#   wt-8298/          tree with EIP-8298 (SETCODEFROM) only
#   wt-both/          tree with EIP-8298 and EIP-8151
# and puts the test package in tests/bogota/ of both trees. Changes are
# staged, not committed, so no git identity is needed.
#
# Main path: fetch the pinned commits by SHA.
#   wt-8298 = EIP8298_COMMIT (execution-specs #3769)
#   wt-both = EIP8298_COMMIT merged with EIP8151_COMMIT (head of #3860
#             when tested), keeping EIP8298_COMMIT's
#             tests/bogota/__init__.py (the one known conflict)
# Fallback path (--use-patch, or if either pinned commit cannot be
# fetched): start from FALLBACK_BASE, the parent of EIP8298_COMMIT on the
# default branch forks/bogota, and apply the patches in patches/.
#   wt-8298 = FALLBACK_BASE + eip-8298-setcodefrom.patch
#   wt-both = wt-8298 + eip-8151-ecrecover.patch
# The 8298 patch also has the three helper files of #3769's test package
# that the test package imports (tests/bogota/eip8298_setcodefrom/
# __init__.py, spec.py, helpers.py). The fallback path fetches only
# FALLBACK_BASE. Its trees differ from the main path's only in tests/ and
# docs/ (src/ and packages/ are the same).
#
# Before the test package is copied, each tree must pass three checks:
# the index hashes to the expected tree, the working tree matches the
# index, and there are no untracked files. Otherwise the script stops.
#
# The script never deletes or overwrites anything: it stops if any of the
# three directories already exists. After a failure, start again with a
# new <work-dir>.

set -euo pipefail

UPSTREAM=https://github.com/ethereum/execution-specs.git
# EIP-8298 SETCODEFROM: execution-specs #3769 as squashed into
# eips/bogota/eip-8298 on 2026-10-19
EIP8298_COMMIT=30efe094153f6708c689bfd3fce4d7fd27ec6b82
# EIP-8151: head of execution-specs PR #3860 when the PoC was tested
EIP8151_COMMIT=623f4593eb0a0f45aebd4a366af0d37e304c5897
# Parent of EIP8298_COMMIT, on the default branch forks/bogota
FALLBACK_BASE=e762bc8260fb44fcf748f836deda8ef39d2bb171

# Expected trees (git write-tree)
MAIN_TREE_8298=ea7a4744503fc8177dcd0a54f65dbbd3e4ee793d
MAIN_TREE_BOTH=2f0ad71f08e4ccbe786ff80a5fc324e80d8e6c70
FALLBACK_TREE_8298=3ab7e043c170b4d5b18f9d4fb70f52965ac81ace
FALLBACK_TREE_BOTH=222a22da89abae199425774313f635b6d8c93be5

fail() {
    echo "setup.sh: $*" >&2
    exit 1
}

usage() {
    echo "usage: $0 <work-dir> [--use-patch]" >&2
    exit 2
}

[ $# -ge 1 ] && [ $# -le 2 ] || usage
WORK=$1
USE_PATCH=0
if [ $# -eq 2 ]; then
    [ "$2" = "--use-patch" ] || usage
    USE_PATCH=1
fi

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
PATCH_8298=$REPO_ROOT/patches/eip-8298-setcodefrom.patch
PATCH_8151=$REPO_ROOT/patches/eip-8151-ecrecover.patch
TESTS=$REPO_ROOT/tests/poc_setcodefrom_migration
for file in "$PATCH_8298" "$PATCH_8151"; do
    [ -f "$file" ] || fail "missing $file"
done
[ -d "$TESTS" ] || fail "missing $TESTS"

mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
ES=$WORK/execution-specs
WT_8298=$WORK/wt-8298
WT_BOTH=$WORK/wt-both
for dir in "$ES" "$WT_8298" "$WT_BOTH"; do
    [ ! -e "$dir" ] || fail "$dir already exists; not touching it"
done

check_tree() {
    # check_tree <worktree> <expected tree>: the index must hash to the
    # expected tree, the working tree must match the index, and there must
    # be no untracked (or ignored) files. The staged changes themselves are
    # expected, since nothing is committed.
    local tree untracked
    tree=$(git -C "$1" write-tree)
    [ "$tree" = "$2" ] || fail "tree of $1 is $tree, expected $2"
    git -C "$1" diff --quiet ||
        fail "$1 has changes that are not in the index"
    untracked=$(git -C "$1" status --porcelain --untracked-files=all \
        --ignored | grep -E '^(\?\?|!!) ' || true)
    [ -z "$untracked" ] || fail "$1 has untracked files: $untracked"
    echo "setup.sh: $(basename "$1"): tree $tree matches"
}

echo "setup.sh: cloning $UPSTREAM"
git clone --quiet --filter=blob:none --no-checkout --single-branch \
    "$UPSTREAM" "$ES"
# This clone is only for reading.
git -C "$ES" remote set-url --push origin DISABLED_NO_PUSH

if [ "$USE_PATCH" -eq 0 ]; then
    for commit in "$EIP8298_COMMIT" "$EIP8151_COMMIT"; do
        if ! git -C "$ES" fetch --quiet origin "$commit"; then
            echo "setup.sh: cannot fetch $commit;" \
                "switching to the fallback path" >&2
            USE_PATCH=1
            break
        fi
    done
fi

if [ "$USE_PATCH" -eq 0 ]; then
    echo "setup.sh: path: main (fetched $EIP8298_COMMIT and $EIP8151_COMMIT)"
    git -C "$ES" worktree add --quiet --detach "$WT_8298" "$EIP8298_COMMIT"
    check_tree "$WT_8298" "$MAIN_TREE_8298"

    git -C "$ES" worktree add --quiet --detach "$WT_BOTH" "$EIP8298_COMMIT"
    # The merge has one known add/add conflict, in the docstring link of
    # tests/bogota/__init__.py. It is resolved by keeping EIP8298_COMMIT's
    # version. Any other conflict stops the script.
    set +e
    merge=$(git -C "$ES" merge-tree --write-tree --name-only --no-messages \
        "$EIP8298_COMMIT" "$EIP8151_COMMIT")
    merge_status=$?
    set -e
    tree=$(printf '%s\n' "$merge" | head -n 1)
    conflicts=$(printf '%s\n' "$merge" | tail -n +2 | sed '/^$/d')
    case "$merge_status" in
        0 | 1) ;;
        *) fail "git merge-tree failed ($merge_status)" ;;
    esac
    [ "$conflicts" = "" ] || [ "$conflicts" = "tests/bogota/__init__.py" ] ||
        fail "unexpected merge conflicts: $conflicts"
    git -C "$WT_BOTH" read-tree -u --reset "$tree"
    if [ -n "$conflicts" ]; then
        echo "setup.sh: resolving $conflicts with $EIP8298_COMMIT's version"
        git -C "$WT_BOTH" checkout "$EIP8298_COMMIT" -- \
            tests/bogota/__init__.py
    fi
    check_tree "$WT_BOTH" "$MAIN_TREE_BOTH"
else
    echo "setup.sh: path: fallback ($FALLBACK_BASE + patches/)"
    git -C "$ES" fetch --quiet origin "$FALLBACK_BASE" ||
        fail "cannot fetch $FALLBACK_BASE"
    git -C "$ES" worktree add --quiet --detach "$WT_8298" "$FALLBACK_BASE"
    git -C "$WT_8298" apply --index "$PATCH_8298"
    check_tree "$WT_8298" "$FALLBACK_TREE_8298"

    git -C "$ES" worktree add --quiet --detach "$WT_BOTH" "$FALLBACK_BASE"
    git -C "$WT_BOTH" apply --index "$PATCH_8298"
    git -C "$WT_BOTH" apply --index "$PATCH_8151"
    check_tree "$WT_BOTH" "$FALLBACK_TREE_BOTH"
fi

for tree_dir in "$WT_8298" "$WT_BOTH"; do
    target=$tree_dir/tests/bogota/poc_setcodefrom_migration
    [ ! -e "$target" ] || fail "$target already exists"
    cp -R "$TESTS" "$target"
done

echo "setup.sh: done. Next: scripts/run.sh $WORK"
