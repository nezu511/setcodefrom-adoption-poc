#!/usr/bin/env bash
# Fill the PoC tests in both trees built by scripts/setup.sh and compare
# the counts with the expected ones.
#
#   scripts/run.sh <work-dir> [--gas]
#
# Writes <work-dir>/fixtures-<tree>/ and <work-dir>/fill-<tree>.log.
# With --gas it instead fills only test_route_a_migration, with the gas
# measurement plugin (tools/measure_gas_plugin.py), and prints the gas of
# each transaction, from <work-dir>/gas-<tree>.jsonl and
# <work-dir>/gas-fixtures-<tree>/.
#
# Stops if any of these outputs already exists (nothing is overwritten).

set -euo pipefail

fail() {
    echo "run.sh: $*" >&2
    exit 1
}

usage() {
    echo "usage: $0 <work-dir> [--gas]" >&2
    exit 2
}

[ $# -ge 1 ] && [ $# -le 2 ] || usage
WORK=$(cd "$1" && pwd)
GAS=0
if [ $# -eq 2 ]; then
    [ "$2" = "--gas" ] || usage
    GAS=1
fi
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
# The Python the tests were checked with; uv downloads it if missing.
export UV_PYTHON=${UV_PYTHON:-3.12}
TESTS=tests/bogota/poc_setcodefrom_migration

declare -A EXPECTED=(
    [wt-both]="254 passed"
    [wt-8298]="246 passed, 8 skipped"
)

outputs=()
for tree in wt-both wt-8298; do
    [ -d "$WORK/$tree/$TESTS" ] || fail "missing $WORK/$tree/$TESTS"
    if [ "$GAS" -eq 1 ]; then
        outputs+=("$WORK/gas-fixtures-$tree" "$WORK/gas-$tree.jsonl")
    else
        outputs+=("$WORK/fixtures-$tree" "$WORK/fill-$tree.log")
    fi
done
for path in "${outputs[@]}"; do
    [ ! -e "$path" ] || fail "$path already exists; not overwriting it"
done

status=0
for tree in wt-both wt-8298; do
    [ "$GAS" -eq 0 ] || break
    echo "run.sh: filling $tree"
    set +e
    (cd "$WORK/$tree" &&
        uv run fill "$TESTS" --fork Bogota -rs \
            --output "$WORK/fixtures-$tree") >"$WORK/fill-$tree.log" 2>&1
    set -e
    summary=$(grep -E '^=+ .*(passed|failed|error).* in [0-9.]+s' \
        "$WORK/fill-$tree.log" | tail -n 1 |
        sed -E 's/^=+ //; s/ in [0-9.]+s.*$//' || true)
    if [ "$summary" = "${EXPECTED[$tree]}" ]; then
        echo "run.sh: $tree: $summary (as expected)"
    else
        echo "run.sh: $tree: '$summary', expected '${EXPECTED[$tree]}'" >&2
        echo "run.sh: see $WORK/fill-$tree.log" >&2
        status=1
    fi
done

if [ "$GAS" -eq 1 ]; then
    for tree in wt-both wt-8298; do
        echo "run.sh: measuring gas in $tree"
        (cd "$WORK/$tree" &&
            PYTHONPATH="$REPO_ROOT/tools" GAS_LOG="$WORK/gas-$tree.jsonl" \
                uv run fill "$TESTS/test_m1_route_a.py" --fork Bogota \
                -k "test_route_a_migration and blockchain_test-" \
                -p measure_gas_plugin \
                --output "$WORK/gas-fixtures-$tree") >/dev/null 2>&1 ||
            fail "gas run failed in $tree"
        (cd "$WORK/$tree" &&
            uv run python - "$WORK/gas-$tree.jsonl" \
                "$WORK/gas-fixtures-$tree" <<'EOF'
import json
import sys
from pathlib import Path

log, fixtures = Path(sys.argv[1]), Path(sys.argv[2])
print(f"{'test':<10} {'tx':>2} {'gas used':>10} {'execution':>10} {'state':>10}")
seen: dict[str, int] = {}
for line in log.read_text().splitlines():
    row = json.loads(line)
    case = row["test"].split("-")[-1].split("]")[0]
    seen[case] = seen.get(case, 0) + 1
    print(
        f"{case:<10} {seen[case]:>2} {row['gas_used']:>10,} "
        f"{row['execution_gas_used']:>10,} {row['state_gas_used']:>10,}"
    )
for path in sorted(fixtures.glob("blockchain_tests/**/route_a_migration.json")):
    for name, test in json.loads(path.read_text()).items():
        used = [int(b["blockHeader"]["gasUsed"], 16) for b in test["blocks"]]
        case = name.split("-")[-1].split("]")[0]
        print(f"{case:<12} block gasUsed: " + ", ".join(f"{u:,}" for u in used))
EOF
        )
    done
fi

exit "$status"
