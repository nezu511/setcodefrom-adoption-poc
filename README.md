# SETCODEFROM adoption profile: proof of concept on EELS

This repository is a proof of concept (PoC) for the pre-ERC
**"Adoption Profile and Reference Kernel for EOAs Adopting Code via
SETCODEFROM"**, draft v2.7: posts #1 and #2 of
<https://ethereum-magicians.org/t/30020> as revised on 2026-10-23. Later
revisions of those posts are not covered; v2.7 stays in their edit
history. One exception, a v2.8 candidate: `Migrator` also reads R4's
record after `initialize` (see [Spec claims and PoC choices](#spec-claims-and-poc-choices)).

It runs the draft's migration guard (`MigrationCheck`) and Route A
(EIP-7702 + `Migrator`) on the Python execution specs (EELS,
[ethereum/execution-specs](https://github.com/ethereum/execution-specs)),
using their implementations of
[EIP-8298 (SETCODEFROM)](https://eips.ethereum.org/EIPS/eip-8298), from
[ethereum/execution-specs#3769](https://github.com/ethereum/execution-specs/pull/3769)
by CPerezz (co-authored by marioevz), and
[EIP-8151](https://eips.ethereum.org/EIPS/eip-8151), from
[ethereum/execution-specs#3860](https://github.com/ethereum/execution-specs/pull/3860)
by the author of this PoC.

The same test files are filled against two trees:

| Tree | Contents |
|---|---|
| `wt-both` | EIP-8298 + EIP-8151 |
| `wt-8298` | EIP-8298 only |

Expectations branch on `fork.is_eip_enabled(8151)`. Each test either
checks one claim of the draft or pins one choice this PoC made where v2.7
leaves the point open (see [Spec claims and PoC choices](#spec-claims-and-poc-choices)).

The PoC kernel is **not conforming code**: these trees have no EIP-8141,
so it has no `VERIFY` (R2) and no relay path, and it does not implement
R4's lock. It is there to exercise the guard and Route A, not to be used
as an account. See [Known limits](#known-limits).

Names from the draft: FM1–FM7 are its failure modes, R1–R8 its
requirements on adopted code, and P1–P4 the four checks of
`MigrationCheck`. `D` is the EIP-712 digest of the signed `Migration`, and
`ownerSig` is the old key's signature over `D`. In Route A, one type-4
transaction delegates the EOA to `Migrator` and calls its `migrate`, which
calls `MigrationCheck.begin` (P1), adopts the signed code with
`SETCODEFROM`, runs its `initialize` (P3, then the check of R4's record
described below), and calls `MigrationCheck.finish` (P2, P4), which emits
`Migrated`.

## The four results

| # | Result | Tests (file) | What is asserted |
|---|---|---|---|
| 1 | Route A migration completes and emits `Migrated` | `test_route_a_migration[self_sent/sponsored]` (`test_m1_route_a.py`), wt-both | One type-4 transaction: receipt status 1, exactly one log, `Migrated(account, keccak256(kernel), D, 1)` from `MigrationCheck`. The account's code is the kernel, and every storage slot is compared (the new authority and R4's slot). In the next block: `ecrecover(D, ownerSig)` succeeds with empty output; the new P256 key gives the ERC-1271 magic `0x1626ba7e`; the old key gives `0xffffffff`; ETH with empty calldata and the three ERC-721/1155 hooks are accepted. |
| 2 | Without EIP-8151 the same migration reverts at P4 | the same test, wt-8298; `test_route_a_refusal_reason` | Same inputs: status 0, no log, the account keeps its delegation to `Migrator`, and the old key still recovers and still sends a transaction. With a recorder as executor, the revert reason is `P4Failed`. |
| 3 | Self-recovery locks the account out (FM1) | `test_fm1_self_recovery_while_delegated`, `test_fm1_self_recovery_after_adoption`, `test_fm1_guard_passes_self_recovery` (`test_m2_failure_modes.py`) | A wallet that approves when `ecrecover(hash, sig) == address(this)` (test-only bad example): while delegated, the old key's signature gives `0x1626ba7e` on both trees. After adopting it, the same check gives `0xffffffff` with EIP-8151 and still `0x1626ba7e` without it. The guard adopts this code anyway (`Migrated` is emitted), as the draft's "Inputs, not quality" says; afterwards the old key gives `0xffffffff`. |
| 4 | An account left delegated to `Migrator` still receives (FM4) | `test_fm4_receive_with_migrator_delegation_left` (`test_m2_failure_modes.py`), both trees | After a failed migration that leaves the 7702 delegation to `Migrator`: a 1 wei transfer with empty calldata succeeds (with its EIP-7708 `Transfer` log), the three hooks return their selectors, and 1 wei sent by a `CALL` that forwards 0 gas (the 2,300 stipend only) succeeds. A sender that hard-codes 21,000 gas still fails against such an account (see FM4 below). |

## Map from the draft to the tests

"direct" means the relayer's transaction itself reverts (status 0, no log)
and the account keeps its delegation and storage. "recorded" means a
test-only recorder makes the call and stores `success`, `returndatasize`
and the first word of the output; for a revert the test asserts the custom
error's selector.

### Failure modes

FM2 and FM7 are out of scope (see [Known limits](#known-limits)).

| Draft | Tests | What they show |
|---|---|---|
| FM1. Self-recovery locks the account out | `test_fm1_*` (3 tests) | Result 3 above. |
| FM3. Adopted but not initialized | `test_fm3_adopted_not_initialized`, `test_fm3_adopted_not_initialized_cannot_send`, `test_route_a_rejected[initialize_not_recorded]` | Kernel adopted without `initialize`: the new key's valid signature gives `0xffffffff`; `initialize` from outside reverts with `NotSelf`; a 7702 authorization signed by the account is skipped (nonce and code unchanged); a transaction from the old key is rejected (`SENDER_NOT_EOA`, EIP-3607). Through `Migrator`, code whose fallback accepts every selector makes the `initialize` call succeed with nothing initialized; `Migrator` refuses it with `NotInitialized` (a v2.8 candidate, see below). |
| FM4. Receiving breaks | `test_fm4_receive_with_migrator_delegation_left`, `test_fm4_kernel_receives_on_stipend`, `test_fm4_code_without_receive_path` | Result 4; the kernel receives on the stipend alone (wt-both); code without a receive path makes the transfer and the three hooks fail. |
| FM4. "Senders that hard-code 21,000 gas can fail against almost any code, a 7702 delegation included" | `test_fm4_plain_transfer_with_21000_gas[eoa/migrator_delegated/kernel_adopted]` | A 1 wei transfer with a 21,000 gas limit: status 1 to an EOA without code, status 0 to an account delegated to `Migrator` (the 7702 delegation case, observed directly) and to an account with the kernel. The whole 21,000 is used. See the note on gas in [Known limits](#known-limits). |
| FM5. The source can change | `test_fm5_source_replaced_after_signing` | The source replaces its own code after the owner signed its hash: `SourceHashMismatch`. |
| FM6. An empty `ecrecover` result proves nothing | `test_fm6_p1_refuses_other_signer_without_code`, `test_fm6_ecrecover_of_signer_with_code`, `test_fm6_p1_p4_against_fake_ecrecover`, `test_ecrecover_of_zero_r_signature`, `test_begin_finish_link[other_signature]` | Another key without code signs `D`: `P1Failed`. For a signer with code, ecrecover gives empty output with EIP-8151 and the signer's address without it. An r = 0 signature gives `success 1` and empty output on both trees. A `finish` with such a broken signature after a valid `begin` is refused (`NotBegun`), because P4 must use the `ownerSig` that P1 accepted (v2.7, P4). |

### Guard checks and errors

All 22 custom errors of the PoC contracts are asserted by selector in at
least one test. Tests marked "(PoC choice)" pin a choice that v2.7 leaves
open; see [Spec claims and PoC choices](#spec-claims-and-poc-choices).

| Draft | Contract and error | Tests |
|---|---|---|
| P1: `ecrecover(D, ownerSig)` succeeds and returns the account | `MigrationCheck.begin`, `P1Failed` | `test_route_a_rejected[broken_owner_signature/other_signer_with_code]`, `test_fm6_p1_refuses_other_signer_without_code`, `test_fm6_p1_p4_against_fake_ecrecover[p1_reverts_with_owner]` |
| P1 while delegated (EIP-8151 exempts delegation indicators) | — | `test_p1_while_delegated` |
| P2: `EXTCODEHASH(account) == codeHash` after adoption | `finish`, `P2Failed` | `test_fm5_adopted_code_replaces_itself` (the adopted code replaces itself in `initialize`) |
| P3: `initialize(initData)` ran and `keccak256(initData) == initDataHash` (Route A: `Migrator`) | `Migrator`, `InitDataMismatch`, `InitializeFailed`, `NotInitialized` (PoC choice, a v2.8 candidate) | `test_route_a_rejected[init_data_swapped/bad_registration_proof/initialize_not_recorded]`, `test_kernel_initialize_rejected` |
| P4: the same call, with the `ownerSig` P1 accepted, succeeds with empty output | `finish`, `P4Failed`, `NotBegun` | Result 2; `test_fm6_p1_p4_against_fake_ecrecover[empty_output/p4_call_reverts/zero_word]`; `test_begin_finish_link[other_signature]` |
| `begin` tells the routes apart | `UnsupportedRoute` | `test_begin_unsupported_route_other_delegate`, `test_begin_unsupported_route_eoa_without_code` (Route A only; see [Known limits](#known-limits)) |
| `begin`: `p.check == address(this)`, deadline (valid while `block.timestamp <= deadline`), revocation | `WrongCheck`, `Expired`, `Revoked` | `test_begin_wrong_check`, `test_begin_deadline[at_deadline/expired]`, `test_begin_revoked` |
| `finish` emits `Migrated` at most once per `begin`; the link is keyed by `(account, D)`, holds `keccak256(ownerSig)` and is consumed by `finish` | `NotBegun` | `test_begin_finish_link[finish_only/other_signature/finish_twice]`, `test_adopted_initialize_calls_finish` |
| `Migrator`: never at its own address; `msg.sender == p.executor`; reverts if the executor is `ENTRY_POINT` | `AtMigratorAddress`, `NotExecutor`, `ExecutorIsEntryPoint` | `test_migrator_at_own_address`, `test_migrator_not_executor`, `test_migrator_executor_is_entry_point` |
| `Migrator`: fail early on the source's hash; `SETCODEFROM` must return 1 | `SourceHashMismatch`, `SetCodeFailed` | `test_route_a_rejected[code_hash_mismatch]`, `test_fm5_source_replaced_after_signing`, `test_fm5_setcodefrom_fails_on_delegated_source` |
| `ownerSig` length | `BadSignatureLength` | `test_bad_signature_length` (PoC choice) |
| Kernel R4: only the account itself; revert if the recorded code hash equals `EXTCODEHASH(this)`; at least one execution-capable authority with a valid proof | `NotSelf`, `AlreadyInitialized`, `NotExecutionCapable`, `InvalidRegistration` | `test_template_is_inert`, `test_fm3_adopted_not_initialized`, `test_kernel_initialize_rejected[already_initialized/bad_registration_proof/not_execution_capable]` |
| Kernel: the layout of `initData` | `BadInitData` | `test_kernel_initialize_rejected[verifier_high_bits/scope_over_8_bits]` (PoC choice) |
| Kernel R4: "Authority data already in storage (for example, from an earlier 7702 delegate) has no effect; the code need not clear it" | — | `test_kernel_ignores_prior_storage`, `test_prior_working_authority_void_after_migration` |
| Kernel R8: only execution-capable authorities | — | `test_is_valid_signature_scope` |
| "Completion": confirm by `Migrated`, not by transaction success | — | `test_completion_with_skipped_authorization`: the authorization's nonce does not match, so it is skipped; `migrate` hits empty code; status 1 and no log; the account keeps empty code and nonce 0 |
| "Already-delegated EOAs" | — | `test_kernel_initialize_rejected[already_initialized]` (R4's slot already holds the kernel's hash), `test_kernel_ignores_prior_storage`, `test_prior_working_authority_void_after_migration` (the account starts delegated to an earlier delegate, with its storage) |
| "Missing EIP-8151 is caught" | — | Result 2 |
| "The reference template is inert" | — | `test_template_is_inert` |

In `test_prior_working_authority_void_after_migration`, a control account
with the kernel and the same earlier authority slots shows that the
earlier authority does verify (`0x1626ba7e`) before migration. After the
migration (wt-both), every storage slot of the account is compared and the
earlier key gives `0xffffffff`.

## Spec claims and PoC choices

Most tests check a claim of v2.7. For the five below, which pin a precise
behavior of the guard, the table gives where v2.7 states it:

| Test | Where v2.7 states it |
|---|---|
| `test_fm6_p1_p4_against_fake_ecrecover[zero_word]`: P4 refuses 32 zero bytes | The P1–P4 table (P4: "succeeds with empty output"); P1/P4 details, "Only empty output" ("P4 accepts only `success = 1` with empty output") |
| `test_begin_deadline[at_deadline]`: `begin` passes at `block.timestamp == deadline` | "How `begin` tells the routes apart" ("valid while `block.timestamp <= deadline`") |
| `test_begin_finish_link[other_signature]`: `finish` with another `ownerSig` reverts | The P1–P4 table (P4: "with the `ownerSig` P1 accepted"); the `finish` paragraph ("It reverts unless P4 uses the `ownerSig` that P1 accepted"); Route A details, "Linking `begin` and `finish`" |
| `test_begin_finish_link[finish_twice]`, `test_adopted_initialize_calls_finish`: a second `finish` reverts (observed in `wt-both`; in `wt-8298` the first `finish` already reverts at P4) | The `finish` paragraph ("emits `Migrated` at most once per `begin`"); Route A details, "Linking `begin` and `finish`" ("`finish` consumes the link, so a second `finish` reverts") |
| `test_migrator_executor_is_entry_point`: `Migrator` reverts with `ExecutorIsEntryPoint` | Route A details, "Executor" ("reverts if `p.executor` is EIP-8141's `ENTRY_POINT`"), and the pseudo-code (`require p.executor != ENTRY_POINT`) |

Some docstrings in the tests and contracts were written before v2.7 was
posted and call these points "PoC choices", "v2.7 candidates" or "ahead of
draft v2.7". The table above reflects the posted v2.7.

The tests below still pin a choice of this PoC where v2.7 does not decide.
They would move to the first table only if a later draft adopts the same
choice.

| PoC choice | Test |
|---|---|
| `ownerSig` must be 65 bytes. | `test_bad_signature_length` |
| The layout of `initData`, and `BadInitData` for malformed words. v2.7 says the layout "is implementation-defined in this draft". | `test_kernel_initialize_rejected[verifier_high_bits/scope_over_8_bits]` |
| **A check beyond v2.7 (a v2.8 candidate).** After the `initialize` call, `Migrator` requires `SLOAD(INITIALIZED_CODE_HASH_SLOT) == EXTCODEHASH(this)` and otherwise reverts with `NotInitialized`. v2.7's pseudo-code (`require address(this).call(initialize(initData))`) and `finish` (P2, P4) do not read R4's record. Without this check, code whose fallback accepts every selector, such as a Safe with no fallback handler set, passes P1–P4 with nothing initialized: the `initialize` call succeeds and does nothing. | `test_route_a_rejected[initialize_not_recorded]` (test-only code from `harness.py`: `bad_example_permissive_fallback_code`) |

With the check removed from `Migrator`, `test_route_a_rejected[initialize_not_recorded]`
fails: the migration completes and `Migrated` is emitted (checked on
`wt-both`).

Because of the check, the test-only adopted code that must get through
Route A writes R4's record in its `initialize`, as the kernel does
(`record_initialization` in `harness.py`): the self-recovering wallet, the
code whose `initialize` calls `finish`, and the source that replaces the
account's code (its record names the replacement, so `Migrator`'s check
passes and `finish` stops it at P2). The expected storage of
`test_fm1_guard_passes_self_recovery` and of the control case of
`test_adopted_initialize_calls_finish` therefore holds the record.

`test_adopted_initialize_calls_finish` uses test-only adopted code whose
`initialize` calls `MigrationCheck.finish(p, ownerSig)` itself and ignores
the result. With EIP-8151, `Migrator`'s own `finish` then reverts with
`NotBegun` and the whole migration reverts, as v2.7's "Linking `begin` and
`finish`" describes. Without EIP-8151, `Migrator`'s `finish` reverts with
`P4Failed`, as in the control; the test does not observe what the inner
call did. In a control case, `initialize` only writes R4's record and the
migration completes with one `Migrated`.

## Known limits

- **The kernel is not conforming code.** These trees have no EIP-8141, so
  the kernel has no `VERIFY` (R2) and no relay path.
- **`MigrationCheck` implements Route A only.** v2.7's `begin` treats a
  caller with empty code as Route B ("empty code means Route B"), which
  reads the frames of an EIP-8141 transaction. This PoC's `begin` reverts
  with `UnsupportedRoute` instead. `test_begin_unsupported_route_eoa_without_code`
  checks only that the call reverts, so it does not tell the two apart.
- **R4's lock is not implemented.** v2.7's R4 ends with "finally locks the
  account" for the rest of the frame or transaction. The kernel's
  `initialize` does not lock, and no test covers the lock.
- **The kernel reads its authority without checking that `initialize`
  ran.** `isValidSignature` does not look at R4's record. v2.7's R4 treats
  as authorities "only what this initialization wrote", so code adopted
  without `initialize` (FM3) would accept authority data already in the
  kernel's slots. Route A always runs `initialize`, which writes every
  slot the kernel reads. `test_is_valid_signature_scope` and the control
  account in `test_prior_working_authority_void_after_migration` rely on
  this behavior.
- **The check of R4's record is not a quality check.** Code that writes
  `INITIALIZED_CODE_HASH_SLOT` and installs nothing passes it (the
  self-recovering wallet does). It stops code that never ran an
  initialization, not code that pretends to. It does not replace choosing
  a code hash that has been checked against the profile ("Inputs, not
  quality").
- **A stale record is not handled (not tested).** If the account's storage
  already holds the new code's hash at `INITIALIZED_CODE_HASH_SLOT` (left
  by an earlier delegate), conforming code reverts in `initialize` (R4),
  but code with a permissive fallback would satisfy the check without
  running anything. Reading the slot before `SETCODEFROM` and requiring
  that it differs from `p.codeHash` would close this; this PoC does not.
- **Route B is not covered by the check.** Its `finish` is a different
  contract and cannot read the account's storage, and frames do not pass
  return data to later frames, so it would need a getter on the account.
  That would add a second interface to the profile, so it is an open
  question, not part of this PoC.
- **No replacement path, so R6 is not tested.** The kernel has no entry
  that replaces its code; `test_contract_opcodes` checks that its bytecode
  has no `SETCODEFROM` opcode. It also has no entry for authority changes
  (R5) after `initialize`.
- **Placeholders.** Values that v2.7 marks TBD or does not fix are this
  PoC's own, not proposals: the EIP-712 domain `name` and `version`
  (`DOMAIN_NAME`, `DOMAIN_VERSION`) and the scope bits (`SCOPE_PAYMENT`,
  `SCOPE_EXECUTION`) in `helpers.py`; the storage namespace
  (`KERNEL_NAMESPACE`) and the slot of R4's record
  (`INITIALIZED_CODE_HASH_SLOT`, which v2.7 says this ERC will fix) in
  `contracts.py`; the route number in `Migrated` (`ROUTE_A = 1`, in
  `contracts.py`); and the ERC-1271 wrapping `AccountMessage(bytes32 hash)`
  (`helpers.py`), one of the options in v2.7's Q8.
- **The old key as an authority** ("Limits of the guard") is not tested.
  In v2.7, checking that the old key can satisfy none of the installed
  authorities is a wallet requirement ("Old key"), not something the guard
  or the code checks. R1 itself asks the code never to authorize via
  secp256k1 recovery against its own address; the kernel makes no
  `ecrecover` call, but no test checks that.
- **The nested-replacement test raised by Revinand in the Magicians thread is not in this PoC.** v2.7's Next
  steps place it in the conformance suite.
- **One chain.** These trees model a single chain. Nothing here covers
  transactions or messages that reach the account from another chain,
  such as the OP Stack deposits raised in post #16 of the Magicians
  thread.
- **Out of scope:** Route B, FM2 (needs EIP-8141) and FM7 are planned for
  a second PoC that integrates EIP-8141. v2.7's wallet requirements are
  not covered, since there is no wallet here (the "Old key" check is
  noted above).
- **Test-only tools.** Some tests use contracts that are not reference
  implementation: bad examples of adopted code, sources that change, a
  fake ecrecover at another address, a stipend sender, a step harness that
  calls `begin`, `SETCODEFROM`, `initialize` and `finish` in any order, a
  recorder, and code whose `initialize` calls `finish`. They live in
  `harness.py` (and the recorder in a separate section of `contracts.py`),
  apart from the reference contracts (verifier, kernel, `MigrationCheck`,
  `Migrator`).
- **Some forms cannot be built in these trees.** `ExecutorIsEntryPoint` has
  only the recorded form (no key exists for `0xaa`, so no transaction can
  come from it). `UnsupportedRoute` for an EOA without code has only the
  direct form (the caller must be the EOA itself).
- **Gas values depend on the current EIP-8037 draft** in this tree
  (`COST_PER_STATE_BYTE = 1530`). If the draft changes, the values change.
- **The 21,000 gas transfer** result (FM4) comes from this tree's EIP-2780
  intrinsic gas (Bogota, which inherits Amsterdam): a value transfer to an
  account costs exactly 21,000 here (12,000 + 3,000 cold recipient +
  6,000 value), so the call starts with no gas.

## Pinned commits

The results are for the pinned commits below. They were not run on the
current heads of the upstream branches (which now include EIP-8141).

| What | Commit |
|---|---|
| EIP-8298: execution-specs #3769 as squashed into `eips/bogota/eip-8298` on 2026-10-19 | `30efe094153f6708c689bfd3fce4d7fd27ec6b82` |
| EIP-8151: head of execution-specs PR #3860 when this PoC was tested | `623f4593eb0a0f45aebd4a366af0d37e304c5897` |
| Parent of the first, on the default branch `forks/bogota` | `e762bc8260fb44fcf748f836deda8ef39d2bb171` |

The upstream branches have since been rebased. Checked on 2026-10-24 with
a fresh mirror clone of execution-specs (all branches, tags and
`refs/pull/*`):

- Neither `30efe094` nor `623f4593` is reachable from any ref. Both could
  still be fetched by SHA. `e762bc82` is in the history of `forks/bogota`.
- The body of `setcodefrom()` (`src/ethereum/forks/bogota/vm/instructions/system.py`)
  is the same in `30efe094` and in the rebased #3769 commit.
- `src/ethereum/forks/bogota/vm/precompiled_contracts/ecrecover.py` is the
  same blob in `623f4593` and in the #3860 commit merged into
  `eips/bogota/eip-8151`. So are `eip_8151.py`, `forks.py` and
  `account_types.py` under `packages/testing/`; the change to
  `base_fork.py` is the same.

`scripts/setup.sh` builds the two trees in one of two ways and checks
every tree by `git write-tree`, because the merge is left staged, not
committed, and a commit's hash depends on its author and time.

| Path | `wt-8298` | `wt-both` |
|---|---|---|
| Main: fetch the two pinned commits by SHA | `30efe094` (tree `ea7a4744503fc8177dcd0a54f65dbbd3e4ee793d`) | `30efe094` merged with `623f4593` (tree `2f0ad71f08e4ccbe786ff80a5fc324e80d8e6c70`) |
| Fallback: `--use-patch`, or if either commit cannot be fetched | `e762bc82` + `patches/eip-8298-setcodefrom.patch` (tree `3ab7e043c170b4d5b18f9d4fb70f52965ac81ace`) | the same + `patches/eip-8151-ecrecover.patch` (tree `222a22da89abae199425774313f635b6d8c93be5`) |

- The merge has one add/add conflict, in the docstring link of
  `tests/bogota/__init__.py`; the script keeps `30efe094`'s version and
  stops on any other conflict.
- The fallback path fetches only `e762bc82`, never the two pinned commits.
  (If the main path fails to fetch `623f4593` and switches to the
  fallback, `30efe094`, fetched just before, stays in the clone unused.)
- The fallback trees have the same `src/` and `packages/` as the main
  trees. They differ only in `tests/` and `docs/`. They lack:
  - #3769's tests in `tests/bogota/eip8298_setcodefrom/` (all files there
    but `__init__.py`, `spec.py` and `helpers.py`, which the test package
    imports) and its change to one file in `tests/ported_static/`;
  - #3860's tests in `tests/bogota/eip8151_account_code_restricted_ecrecover/`
    and its changes to six ecrecover tests in `tests/ported_static/` and
    `tests/frontier/`;
  - one docs page.
- Before the test package is copied in, each tree must also match its
  index, with no untracked files. The script prints which path it used.

## Requirements

- Tested on Linux. macOS was not tested. `scripts/run.sh` needs bash 4 or
  later.
- git 2.38 or later (for `git merge-tree --write-tree`)
- [uv](https://docs.astral.sh/uv/). `scripts/run.sh` sets `UV_PYTHON=3.12`
  unless you set it yourself, and uv downloads Python 3.12 if it is
  missing. (With no Python 3.11-3.14 installed and no pin, uv picked a
  newer Python for which a dependency, `lxml`, had to be built from source
  and failed.)
- Network access to GitHub and PyPI

Tested with git 2.53.0, uv 0.13.1 and Python 3.12.15.

## Reproduce

```bash
git clone https://github.com/nezu511/setcodefrom-adoption-poc.git
cd setcodefrom-adoption-poc
scripts/setup.sh ../work          # clones execution-specs, builds both trees
scripts/run.sh ../work            # fills the tests in both trees
scripts/run.sh ../work --gas      # optional: measures gas (see below)
```

`run.sh` prints the passed/failed/skipped counts of each tree and whether
they match the expected ones. To build the trees from the patches instead
of fetching the pinned commits:

```bash
scripts/setup.sh ../work-patch --use-patch
scripts/run.sh ../work-patch
```

The scripts stop if a directory or output they would write already
exists. They never delete anything. If a step fails, start again with a
new work directory.

## Expected results

| Tree | passed | failed | skipped |
|---|---|---|---|
| `wt-both` | 246 | 0 | 0 |
| `wt-8298` | 238 | 0 | 8 |

The same counts are expected on both paths. The 8 tests skipped in `wt-8298` are the
ones that only make sense once the migration completes:
`test_old_key_rejected_after_migration`,
`test_fm1_guard_passes_self_recovery` and
`test_fm4_kernel_receives_on_stipend`, each in two fixture formats (and
two parameters for the first).

## Gas

`tools/measure_gas_plugin.py` is a pytest plugin that wraps EELS's
`settle_transaction_gas` at run time (no file under `src/` changes) and
logs the gas of each transaction. `scripts/run.sh --gas` runs it on
`test_route_a_migration`.

| Transaction | Tree | Execution gas | State gas | Paid by sender |
|---|---|---|---|---|
| Create `Migrator` (758 bytes) | both | 73,216 (calldata floor) | 1,343,340 | 1,378,033 |
| Create `MigrationCheck` (1,177 bytes) | both | 100,032 (calldata floor) | 1,984,410 | 2,026,518 |
| Migration, sponsored | wt-both | 156,579 | 622,710 | 779,289 |
| Migration, self-sent | wt-both | 144,579 | 622,710 | 767,289 |
| Migration, sponsored, reverts at P4 | wt-8298 | 154,163 | 35,190 | 189,353 |
| Migration, self-sent, reverts at P4 | wt-8298 | 142,163 | 35,190 | 177,353 |

"Paid by sender" is not always execution + state: for the two creations
the execution column shows the calldata floor, which in this table
affects only the execution column.

The state gas matches these formulas with `COST_PER_STATE_BYTE = 1530`:

| Value | Formula |
|---|---|
| 622,710 | (6 × 64 + 23) × 1,530, where 6 is the number of new storage slots and 23 the length of the delegation indicator |
| 35,190 | 23 × 1,530 (the delegation stays even though the call reverts) |
| 1,343,340 | (758 + 120) × 1,530 |
| 1,984,410 | (1,177 + 120) × 1,530 |
| 3,327,750 | 1,343,340 + 1,984,410, the `gasUsed` of the block that creates both contracts (a block's `gasUsed` is the larger of its execution and state totals) |

## Layout

```
README.md
LICENSE
tests/poc_setcodefrom_migration/   test package (copied to tests/bogota/ of both trees)
  contracts.py                     reference contracts: verifier, kernel, MigrationCheck, Migrator (+ recorder)
  harness.py                       test-only tools (not reference implementation)
  helpers.py, scenarios.py         shared test helpers
  test_m0_*.py ... test_m3_*.py    the tests
scripts/setup.sh                   builds the two trees at the pinned commits (or from the patches)
scripts/run.sh                     fills the tests and checks the counts
patches/eip-8298-setcodefrom.patch e762bc82 -> 30efe094, src/, packages/, tests/bogota/__init__.py and 3 test helpers
patches/eip-8151-ecrecover.patch   30efe094 -> the merge with 623f4593, src/ and packages/
tools/measure_gas_plugin.py        gas measurement plugin
```

## Provenance of the patches

Both patches are diffs of ethereum/execution-specs, made with
`git diff --binary --full-index`:

| Patch | From | Diff | Files |
|---|---|---|---|
| `eip-8298-setcodefrom.patch` | #3769 (EIP-8298), commit `30efe094` | `e762bc82 30efe094 -- src packages tests/bogota/__init__.py tests/bogota/eip8298_setcodefrom/__init__.py tests/bogota/eip8298_setcodefrom/spec.py tests/bogota/eip8298_setcodefrom/helpers.py` | 21 |
| `eip-8151-ecrecover.patch` | #3860 (EIP-8151), commit `623f4593` | `30efe094 <30efe094 merged with 623f4593> -- src packages` | 7 |

The 8298 patch also has three files of #3769's test package
`tests/bogota/eip8298_setcodefrom/`, because the tests here import from
them: `__init__.py` (the package), `spec.py` (`ref_spec_8298`) and
`helpers.py` (`SENTINEL`, `ADOPT_FROM_CALLDATA`, `RESULT_SLOT`, `word`).
Without them the tests stop at import on the fallback path. The tests
of the two pull requests under `tests/` (the `test_*.py` files, the
checklists and the changed existing tests) and their docs are not
included. The unit tests that they change under `packages/testing/`
(two in the 8298 patch, two in the 8151 patch) are included, as part of
`packages/`.
In execution-specs, the root license is CC0-1.0, and
`packages/testing/pyproject.toml` declares `license = "MIT"`.

## Author and license

Author: nezu511.

The files in `patches/` are diffs of ethereum/execution-specs (see
[Provenance of the patches](#provenance-of-the-patches)).

License: CC0-1.0 (see `LICENSE`), except `patches/`, which keep the
licenses of the files they change in execution-specs.
