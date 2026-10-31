"""
Test each check of the Route A guard (`MigrationCheck.begin`/`finish`,
`Migrator`) and of the reference kernel's `initialize`/`isValidSignature`,
so that every custom error is reached by at least one test.

Each refusal is written in two forms where possible: `direct` (the whole
transaction reverts and the delegation stays) and `recorded` (the recorder
pins the custom error). The step harness and the recorder are test-only
tools. Expectations branch on `fork.is_eip_enabled(8151)`.
"""

from dataclasses import replace
from typing import Dict, List

import pytest
from eth_abi import encode
from execution_testing import (
    EOA,
    Account,
    Address,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Fork,
    Hash,
    Op,
    StateTestFiller,
    Storage,
    Transaction,
    TransactionReceipt,
)

from ..eip8298_setcodefrom.spec import ref_spec_8298
from .contracts import (
    AUTHORITY_KEY,
    AUTHORITY_KEY_LENGTH,
    AUTHORITY_SCOPE,
    AUTHORITY_VERIFIER,
    BEGIN,
    ENTRY_POINT,
    ERC1271_MAGIC,
    FINISH,
    INITIALIZED_CODE_HASH_SLOT,
    INVALID,
    code_hash,
    migration_check_code,
    recorder_code,
    verifier_code,
)
from .harness import (
    STEP_CALL,
    STEP_SET_CODE,
    bad_example_permissive_fallback_code,
    step,
    tool_step_harness_code,
)
from .helpers import (
    REGISTRATION_TYPEHASH,
    SCOPE_PAYMENT,
    Migration,
    P256Key,
    account_message_digest,
    init_data,
    keccak,
    owner_signature,
    registration_digest,
    typed_digest,
)
from .scenarios import (
    attempt,
    call_with_intent,
    delegated_to,
    initialize_calldata,
    kernel_hash,
    migrated_log,
    refusal_without_8151,
    revoke_calldata,
    with_form,
)
from .test_m1_route_a import (
    CHAIN_ID,
    GAS_LIMIT,
    KERNEL,
    MESSAGE_HASH,
    NEW_KEY,
    OTHER_KEY,
    SCOPE,
    Deployment,
    deploy,
    deploy_recorder,
    intent,
    is_valid_signature,
    kernel_storage,
    migrate_calldata,
    record,
    recorded,
    registration,
    selector_word,
)

REFERENCE_SPEC_GIT_PATH = ref_spec_8298.git_path
REFERENCE_SPEC_VERSION = ref_spec_8298.version

pytestmark = pytest.mark.valid_from("EIP8298")

MIGRATION_TIMESTAMP = 1_000_000


def authorize(owner: Address, target: Address, nonce: int = 0) -> List:
    """Return the authorization list that delegates `owner` to `target`."""
    return [AuthorizationTuple(address=target, nonce=nonce, signer=owner)]


def run_rejected(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    *,
    deployment: Deployment,
    owner: EOA,
    relayer: EOA,
    recorder: Address,
    p: Migration,
    init: bytes,
    signature: bytes,
    via_recorder: bool,
    reason: str | None,
    blocks_before: List[Block] | None = None,
    auth_nonce: int = 0,
    owner_storage: Dict[int, int] | None = None,
    migration_block: Dict | None = None,
    extra_post: Dict | None = None,
) -> None:
    """
    Run `migrate(p, init, signature)` on `owner` delegated to Migrator, in
    the block after `blocks_before`, and check its outcome: `reason` (a
    custom error) refuses it and leaves the delegation and storage; None
    adopts the kernel and emits `Migrated`.
    """
    digest = p.digest(CHAIN_ID, owner)
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(p, init, signature),
        via_recorder=via_recorder,
        reason=reason,
        authorization=authorize(owner, deployment.migrator, auth_nonce),
        logs=[migrated_log(deployment.check, owner, kernel_hash(), digest)],
    )
    if reason is None:
        owner_post = Account(
            code=KERNEL,
            nonce=auth_nonce + 1,
            storage=kernel_storage(deployment.verifier, NEW_KEY),
        )
    else:
        owner_post = delegated_to(
            deployment.migrator, nonce=auth_nonce + 1, storage=owner_storage
        )
    post: Dict = {**deployment.post(), owner: owner_post}
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    post.update(extra_post or {})
    blockchain_test(
        pre=pre,
        blocks=[
            deployment.block,
            *(blocks_before or []),
            Block(txs=[run.tx], **(migration_block or {})),
        ],
        post=post,
    )


def setup(pre: Alloc, via_recorder: bool) -> tuple:
    """Deploy the contracts and fund the owner, relayer and recorder."""
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    executor = recorder if via_recorder else relayer
    return deployment, owner, relayer, recorder, executor


# ---------------------------------------------------------------------------
# B1. begin
# ---------------------------------------------------------------------------


@with_form
def test_begin_wrong_check(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    Test an intent that names another `MigrationCheck` deployment (bound
    to the same Migrator) as `p.check`: `begin` reverts with `WrongCheck`.
    """
    deployment, owner, relayer, recorder, executor = setup(pre, via_recorder)
    other_check = pre.deploy_contract(
        migration_check_code(deployment.migrator)
    )
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = replace(intent(deployment, executor, init), check=other_check)
    run_rejected(
        blockchain_test,
        pre,
        deployment=deployment,
        owner=owner,
        relayer=relayer,
        recorder=recorder,
        p=p,
        init=init,
        signature=owner_signature(owner, p.digest(CHAIN_ID, owner)),
        via_recorder=via_recorder,
        reason="WrongCheck",
    )


@with_form
@pytest.mark.parametrize(
    "deadline_offset", [-1, 0], ids=["expired", "at_deadline"]
)
def test_begin_deadline(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    deadline_offset: int,
    via_recorder: bool,
) -> None:
    """
    Test the deadline against the block timestamp: `timestamp - 1` reverts
    with `Expired`; `deadline == timestamp` passes `begin` (the migration
    completes with EIP-8151 and stops at P4 without it).
    """
    deployment, owner, relayer, recorder, executor = setup(pre, via_recorder)
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = replace(
        intent(deployment, executor, init),
        deadline=MIGRATION_TIMESTAMP + deadline_offset,
    )
    run_rejected(
        blockchain_test,
        pre,
        deployment=deployment,
        owner=owner,
        relayer=relayer,
        recorder=recorder,
        p=p,
        init=init,
        signature=owner_signature(owner, p.digest(CHAIN_ID, owner)),
        via_recorder=via_recorder,
        reason="Expired"
        if deadline_offset < 0
        else refusal_without_8151(fork),
        migration_block={"timestamp": MIGRATION_TIMESTAMP},
    )


@with_form
@pytest.mark.parametrize(
    "revoker", ["owner", "other"], ids=["owner_revoked", "other_revoked"]
)
def test_begin_revoked(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    revoker: str,
    via_recorder: bool,
) -> None:
    """
    Test revocation: after the owner calls `revoke(D)` with an ordinary
    transaction of the old key, the migration reverts with `Revoked`.
    Another address revoking the same `D` records only (other, D), and the
    owner's migration is not stopped (it completes with EIP-8151 and stops
    at P4 without it).
    """
    deployment, owner, relayer, recorder, executor = setup(pre, via_recorder)
    other = pre.fund_eoa()
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    digest = p.digest(CHAIN_ID, owner)
    sender = owner if revoker == "owner" else other
    revoke = Transaction(
        sender=sender,
        to=deployment.check,
        data=revoke_calldata(digest),
        gas_limit=GAS_LIMIT,
        expected_receipt=TransactionReceipt(status=1),
    )
    revoked_slot = int.from_bytes(
        keccak(bytes(12) + bytes(sender) + bytes(digest))
    )
    # The owner's revoke takes its nonce 0, so the authorization uses 1.
    auth_nonce = 1 if revoker == "owner" else 0
    run_rejected(
        blockchain_test,
        pre,
        deployment=deployment,
        owner=owner,
        relayer=relayer,
        recorder=recorder,
        p=p,
        init=init,
        signature=owner_signature(owner, digest),
        via_recorder=via_recorder,
        reason="Revoked" if revoker == "owner" else refusal_without_8151(fork),
        blocks_before=[Block(txs=[revoke])],
        auth_nonce=auth_nonce,
        extra_post={
            deployment.check: Account(
                code=migration_check_code(deployment.migrator),
                storage={revoked_slot: 1},
            )
        },
    )


def test_begin_unsupported_route_eoa_without_code(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test an EOA without code calling `begin` directly (Route B's empty code
    is out of scope here): the transaction reverts and nothing is recorded.

    Direct form only: the caller must be the EOA itself, so the recorder
    cannot stand in between. That the revert is `UnsupportedRoute` is shown
    by `test_begin_unsupported_route_other_delegate` (recorded), which
    reaches the same check with a caller whose code is not the indicator.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, owner, init)
    signature = owner_signature(owner, p.digest(CHAIN_ID, owner))
    tx = Transaction(
        sender=owner,
        to=deployment.check,
        data=call_with_intent(BEGIN, p, signature),
        gas_limit=GAS_LIMIT,
        expected_receipt=TransactionReceipt(status=0, logs=[]),
    )
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[tx])],
        post={
            **deployment.post(),
            owner: Account(code=b"", nonce=1, storage={}),
        },
    )


@with_form
def test_begin_unsupported_route_other_delegate(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    Test an account delegated to another contract (the step harness, TEST
    ONLY) calling `begin` of the production `MigrationCheck`: its code is
    not the indicator for this instance's Migrator, so `begin` reverts with
    `UnsupportedRoute`.
    """
    deployment, owner, relayer, recorder, _ = setup(pre, via_recorder)
    harness = pre.deploy_contract(tool_step_harness_code())
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, owner, init)
    signature = owner_signature(owner, p.digest(CHAIN_ID, owner))
    steps = step(
        STEP_CALL, deployment.check, call_with_intent(BEGIN, p, signature)
    )
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=steps,
        via_recorder=via_recorder,
        reason="UnsupportedRoute",
        authorization=authorize(owner, harness),
    )
    post: Dict = {
        **deployment.post(),
        owner: delegated_to(harness, nonce=1),
    }
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post=post,
    )


# ---------------------------------------------------------------------------
# B2. Migrator
# ---------------------------------------------------------------------------


@with_form
def test_migrator_not_executor(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    Test an intent whose executor is a third party, sent by the sponsor
    (direct) or the recorder (recorded): `NotExecutor`.
    """
    deployment, owner, relayer, recorder, _ = setup(pre, via_recorder)
    stranger = pre.fund_eoa()
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, stranger, init)
    run_rejected(
        blockchain_test,
        pre,
        deployment=deployment,
        owner=owner,
        relayer=relayer,
        recorder=recorder,
        p=p,
        init=init,
        signature=owner_signature(owner, p.digest(CHAIN_ID, owner)),
        via_recorder=via_recorder,
        reason="NotExecutor",
    )


@pytest.mark.pre_alloc_mutable
def test_migrator_executor_is_entry_point(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test an intent signed with `p.executor = ENTRY_POINT` (`0xaa`): even
    when the caller is `0xaa`, so `NotExecutor` passes, Migrator reverts
    with `ExecutorIsEntryPoint` (added ahead of draft v2.7).

    Recorded form only: the recorder is placed at `0xaa` (TEST ONLY; this
    tree has no EIP-8141, so nothing else calls from there). A direct form
    would need a transaction sent from `0xaa`, which has no key.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = pre.deploy_contract(recorder_code(), address=ENTRY_POINT)
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, ENTRY_POINT, init)
    signature = owner_signature(owner, p.digest(CHAIN_ID, owner))
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(p, init, signature),
        via_recorder=True,
        reason="ExecutorIsEntryPoint",
        authorization=authorize(owner, deployment.migrator),
    )
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post={
            **deployment.post(),
            owner: delegated_to(deployment.migrator, nonce=1),
            recorder: Account(storage=run.recorder_post),
        },
    )


@with_form
def test_migrator_at_own_address(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    Test `migrate` sent to Migrator's own address: `AtMigratorAddress`, and
    Migrator's code and the owner stay as they were.
    """
    deployment, owner, relayer, recorder, executor = setup(pre, via_recorder)
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    signature = owner_signature(owner, p.digest(CHAIN_ID, owner))
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(p, init, signature),
        via_recorder=via_recorder,
        reason="AtMigratorAddress",
        to=deployment.migrator,
    )
    post: Dict = {
        **deployment.post(),
        owner: Account(code=b"", nonce=0, storage={}),
    }
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post=post,
    )


@with_form
@pytest.mark.parametrize("length", [64, 66], ids=["64_bytes", "66_bytes"])
def test_bad_signature_length(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    length: int,
    via_recorder: bool,
) -> None:
    """
    Test an `ownerSig` of 64 or 66 bytes (Migrator passes it through to
    `begin`): `BadSignatureLength`.
    """
    deployment, owner, relayer, recorder, executor = setup(pre, via_recorder)
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    signature = owner_signature(owner, p.digest(CHAIN_ID, owner))
    signature = (signature + b"\x00")[:length]
    run_rejected(
        blockchain_test,
        pre,
        deployment=deployment,
        owner=owner,
        relayer=relayer,
        recorder=recorder,
        p=p,
        init=init,
        signature=signature,
        via_recorder=via_recorder,
        reason="BadSignatureLength",
    )


# ---------------------------------------------------------------------------
# B3. Linking begin and finish (step harness, TEST ONLY)
# ---------------------------------------------------------------------------


@with_form
@pytest.mark.parametrize(
    "case", ["linked", "finish_only", "other_signature", "finish_twice"]
)
def test_begin_finish_link(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    case: str,
    via_recorder: bool,
) -> None:
    """
    Test the transient link between `begin` and `finish`, with the owner
    delegated to the step harness and a `MigrationCheck` bound to the
    harness (built by the production `migration_check_code`).

    - `linked` (control): begin, SETCODEFROM, initialize, finish with the
      same ownerSig: completes with EIP-8151, `P4Failed` without it.
    - `finish_only`: `finish` without `begin`: `NotBegun`.
    - `other_signature`: `finish` with a broken ownerSig (r = 0), after a
      `begin` with the valid one: `NotBegun`. P4 would accept the broken
      signature's empty output, so this shows the guard itself makes P4 use
      P1's signature (v2.7 candidate 4).
    - `finish_twice`: the linked sequence, then `finish` again: `NotBegun`
      with EIP-8151 (the first `finish` cleared the mark), `P4Failed`
      without it (the first `finish` already reverts).
    """
    deployment, owner, relayer, recorder, executor = setup(pre, via_recorder)
    harness = pre.deploy_contract(tool_step_harness_code())
    check = pre.deploy_contract(migration_check_code(harness))
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = replace(intent(deployment, executor, init), check=check)
    digest = p.digest(CHAIN_ID, owner)
    signature = owner_signature(owner, digest)
    broken = bytes(32) + signature[32:]

    begin = step(STEP_CALL, check, call_with_intent(BEGIN, p, signature))
    adopt = step(STEP_SET_CODE, deployment.template) + step(
        STEP_CALL, owner, initialize_calldata(init)
    )
    if case == "linked":
        steps = (
            begin
            + adopt
            + step(STEP_CALL, check, call_with_intent(FINISH, p, signature))
        )
        reason = refusal_without_8151(fork)
    elif case == "finish_only":
        steps = step(STEP_CALL, check, call_with_intent(FINISH, p, signature))
        reason = "NotBegun"
    elif case == "other_signature":
        steps = (
            begin
            + adopt
            + step(STEP_CALL, check, call_with_intent(FINISH, p, broken))
        )
        reason = "NotBegun"
    elif case == "finish_twice":
        finish = step(STEP_CALL, check, call_with_intent(FINISH, p, signature))
        steps = begin + adopt + finish + finish
        reason = "NotBegun" if fork.is_eip_enabled(8151) else "P4Failed"
    else:
        raise ValueError(f"unknown case: {case}")

    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=steps,
        via_recorder=via_recorder,
        reason=reason,
        authorization=authorize(owner, harness),
        logs=[migrated_log(check, owner, kernel_hash(), digest)],
    )
    if reason is None:
        owner_post = Account(
            code=KERNEL,
            nonce=1,
            storage=kernel_storage(deployment.verifier, NEW_KEY),
        )
    else:
        owner_post = delegated_to(harness, nonce=1)
    post: Dict = {**deployment.post(), owner: owner_post}
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post=post,
    )


# ---------------------------------------------------------------------------
# B4. Kernel (R4, R8)
# ---------------------------------------------------------------------------


def already_delegated_owner(pre: Alloc, storage: Dict[int, int]) -> EOA:
    """
    Return an owner still delegated to an earlier wallet delegate (a stand-in
    that only stops) that left `storage` behind ("Already-delegated EOAs").
    Its nonce is 1, so its next authorization uses nonce 1.
    """
    old_delegate = pre.deploy_contract(Op.STOP)
    left_behind = Storage()
    for slot, value in storage.items():
        left_behind[slot] = value
    return pre.fund_eoa(storage=left_behind, delegation=old_delegate)


def registration_with_scope(
    owner: Address, verifier: Address, key: P256Key, scope: int
) -> bytes:
    """Return `initData` for `key` with `scope`, with a valid proof."""
    digest = registration_digest(
        CHAIN_ID, owner, verifier, key.public_key, scope
    )
    return init_data(verifier, key.public_key, scope, key.sign(digest))


def init_data_case(case: str, owner: Address, verifier: Address) -> bytes:
    """Return the `initData` of a kernel rejection case."""
    if case == "not_execution_capable":
        return registration_with_scope(owner, verifier, NEW_KEY, SCOPE_PAYMENT)
    if case == "bad_registration_proof":
        return registration(owner, verifier, NEW_KEY, prover=OTHER_KEY)
    # Malformed initData whose proof signs the malformed words themselves,
    # as the kernel would hash them, so only `BadInitData` refuses it.
    if case == "verifier_high_bits":
        verifier_word, scope_word = (
            (1 << 160) | int.from_bytes(verifier),
            SCOPE,
        )
    elif case == "scope_over_8_bits":
        verifier_word, scope_word = int.from_bytes(verifier), 0x100 | SCOPE
    else:
        raise ValueError(f"unknown case: {case}")
    digest = raw_registration_digest(
        owner, verifier_word, NEW_KEY.public_key, scope_word
    )
    return encode(
        ["uint256", "bytes", "uint256", "bytes"],
        [verifier_word, NEW_KEY.public_key, scope_word, NEW_KEY.sign(digest)],
    )


def raw_registration_digest(
    owner: Address, verifier_word: int, key: bytes, scope_word: int
) -> Hash:
    """
    Return the `Registration` digest over full 32-byte words, as the kernel
    builds it from initData (no masking of `verifier` or `scope`).
    """
    struct_hash = keccak(
        bytes(REGISTRATION_TYPEHASH)
        + verifier_word.to_bytes(32, "big")
        + bytes(keccak(key))
        + scope_word.to_bytes(32, "big")
    )
    return typed_digest(CHAIN_ID, owner, struct_hash)


KERNEL_REJECTIONS = {
    "already_initialized": "AlreadyInitialized",
    "bad_registration_proof": "InvalidRegistration",
    "not_execution_capable": "NotExecutionCapable",
    "verifier_high_bits": "BadInitData",
    "scope_over_8_bits": "BadInitData",
}


@pytest.mark.parametrize("form", ["direct", "recorded", "inner"])
@pytest.mark.parametrize("case", list(KERNEL_REJECTIONS))
def test_kernel_initialize_rejected(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    case: str,
    form: str,
) -> None:
    """
    Test the kernel's `initialize` refusals inside a migration.

    - `already_initialized`: the owner's R4 slot already holds the kernel's
      hash (left by an earlier delegate, "Already-delegated EOAs");
    - `bad_registration_proof`: the proof is another key's signature;
    - `not_execution_capable`: scope `0x1` (payment only);
    - `verifier_high_bits`, `scope_over_8_bits`: malformed `initData`,
      whose proof is valid over the malformed words.

    `direct` and `recorded` run Route A: the whole migration reverts with
    `InitializeFailed` (Migrator does not bubble the kernel's error), except
    `already_initialized`, which Migrator refuses before `SETCODEFROM` with
    `StaleRecord` (the record already names the kernel; a v2.8 candidate).
    `inner` runs SETCODEFROM and `initialize` as the owner through the step
    harness (TEST ONLY), bypassing Migrator, and records the kernel's own
    error (`AlreadyInitialized` for `already_initialized`). The owner's
    storage stays as it was.
    """
    deployment = deploy(pre)
    if case == "already_initialized":
        owner_storage = {
            INITIALIZED_CODE_HASH_SLOT: int.from_bytes(kernel_hash())
        }
        owner = already_delegated_owner(pre, owner_storage)
        auth_nonce = 1
    else:
        owner_storage = {}
        owner = pre.fund_eoa()
        auth_nonce = 0
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    if case == "already_initialized":
        init = registration(owner, deployment.verifier, NEW_KEY)
    else:
        init = init_data_case(case, owner, deployment.verifier)

    if form == "inner":
        harness = pre.deploy_contract(tool_step_harness_code())
        steps = step(STEP_SET_CODE, deployment.template) + step(
            STEP_CALL, owner, initialize_calldata(init)
        )
        run = attempt(
            sender=relayer,
            owner=owner,
            recorder=recorder,
            calldata=steps,
            via_recorder=True,
            reason=KERNEL_REJECTIONS[case],
            authorization=authorize(owner, harness, auth_nonce),
        )
        blockchain_test(
            pre=pre,
            blocks=[deployment.block, Block(txs=[run.tx])],
            post={
                owner: delegated_to(
                    harness, nonce=auth_nonce + 1, storage=owner_storage
                ),
                recorder: Account(storage=run.recorder_post),
            },
        )
        return

    via_recorder = form == "recorded"
    executor = recorder if via_recorder else relayer
    p = intent(deployment, executor, init)
    run_rejected(
        blockchain_test,
        pre,
        deployment=deployment,
        owner=owner,
        relayer=relayer,
        recorder=recorder,
        p=p,
        init=init,
        signature=owner_signature(owner, p.digest(CHAIN_ID, owner)),
        via_recorder=via_recorder,
        reason="StaleRecord"
        if case == "already_initialized"
        else "InitializeFailed",
        auth_nonce=auth_nonce,
        owner_storage=owner_storage,
    )


@with_form
@pytest.mark.parametrize(
    "prior", ["stale", "other_hash"], ids=["stale", "other_hash"]
)
def test_route_a_prior_record(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    prior: str,
    via_recorder: bool,
) -> None:
    """
    Test Migrator's check of R4's slot before `SETCODEFROM` (a v2.8
    candidate): the owner is still delegated to an earlier delegate that
    left a value at `INITIALIZED_CODE_HASH_SLOT`.

    - `stale`: the value is the hash of the code to adopt, test-only code
      whose fallback accepts every selector (from `harness.py`). Migrator
      reverts with `StaleRecord`, on both trees; nothing is adopted and the
      storage stays. Without the check, the left record would satisfy the
      check after `initialize` with nothing run.
    - `other_hash`: the value is another code's hash (`Op.STOP`), and the
      kernel is adopted through the usual Route A. The slot need not be
      empty: with EIP-8151 the migration completes, emits `Migrated`, and
      the kernel's `initialize` overwrites the record with its own hash.
      Without EIP-8151 it stops at P4 and the storage stays.
    """
    deployment = deploy(pre)
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    executor = recorder if via_recorder else relayer
    if prior == "stale":
        permissive = bad_example_permissive_fallback_code()
        prior_hash = code_hash(permissive)
    else:
        prior_hash = code_hash(Op.STOP)
    owner_storage = {INITIALIZED_CODE_HASH_SLOT: int.from_bytes(prior_hash)}
    owner = already_delegated_owner(pre, owner_storage)
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    if prior == "stale":
        p = replace(
            p,
            source=pre.deploy_contract(permissive),
            code_hash=prior_hash,
        )
        reason: str | None = "StaleRecord"
    else:
        reason = refusal_without_8151(fork)
    run_rejected(
        blockchain_test,
        pre,
        deployment=deployment,
        owner=owner,
        relayer=relayer,
        recorder=recorder,
        p=p,
        init=init,
        signature=owner_signature(owner, p.digest(CHAIN_ID, owner)),
        via_recorder=via_recorder,
        reason=reason,
        auth_nonce=1,
        owner_storage=owner_storage,
    )


JUNK = 0x5EED_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
PROBE_NEW_KEY = 0x10
PROBE_OTHER_KEY = 0x20


def test_kernel_ignores_prior_storage(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test R4's "ignoring authority data already in storage": the owner is
    still delegated to an earlier wallet delegate, and its authority slots
    hold another key, with a 96-byte key length and words up to N+6.

    With EIP-8151 the migration installs the new key over them: the new key
    passes ERC-1271 and the old stored key does not. N+0..N+4 hold the new
    authority; the words after the new key's length (N+5, N+6) are left as
    they were. Without EIP-8151 the migration stops at P4 and the storage
    is untouched.
    """
    deployment = deploy(pre)
    prior = {
        AUTHORITY_VERIFIER: int.from_bytes(deployment.verifier),
        AUTHORITY_SCOPE: SCOPE,
        AUTHORITY_KEY_LENGTH: 96,
        AUTHORITY_KEY: int.from_bytes(OTHER_KEY.public_key[:32]),
        AUTHORITY_KEY + 1: int.from_bytes(OTHER_KEY.public_key[32:]),
        AUTHORITY_KEY + 2: JUNK | 2,
        AUTHORITY_KEY + 3: JUNK | 3,
    }
    owner = already_delegated_owner(pre, prior)
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    recorder = deploy_recorder(pre, PROBE_NEW_KEY, PROBE_OTHER_KEY)
    adopted = fork.is_eip_enabled(8151)
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, relayer, init)
    digest = p.digest(CHAIN_ID, owner)
    migration = Transaction(
        sender=relayer,
        to=owner,
        data=migrate_calldata(p, init, owner_signature(owner, digest)),
        gas_limit=GAS_LIMIT,
        authorization_list=authorize(owner, deployment.migrator, 1),
        expected_receipt=TransactionReceipt(
            status=1 if adopted else 0,
            logs=[migrated_log(deployment.check, owner, kernel_hash(), digest)]
            if adopted
            else [],
        ),
    )
    owner_nonce = 2
    blocks = [deployment.block, Block(txs=[migration])]
    if adopted:
        message = account_message_digest(CHAIN_ID, owner, MESSAGE_HASH)
        probes = [
            Transaction(
                sender=prober,
                to=recorder,
                data=record(
                    base,
                    owner,
                    is_valid_signature(MESSAGE_HASH, key.sign(message)),
                ),
                gas_limit=GAS_LIMIT,
            )
            for base, key in (
                (PROBE_NEW_KEY, NEW_KEY),
                (PROBE_OTHER_KEY, OTHER_KEY),
            )
        ]
        blocks.append(Block(txs=probes))
        owner_post = Account(
            code=KERNEL,
            nonce=owner_nonce,
            storage={
                **kernel_storage(deployment.verifier, NEW_KEY),
                AUTHORITY_KEY + 2: JUNK | 2,
                AUTHORITY_KEY + 3: JUNK | 3,
            },
        )
        post: Dict = {
            owner: owner_post,
            recorder: Account(
                storage={
                    **recorded(
                        PROBE_NEW_KEY, 1, 32, selector_word(ERC1271_MAGIC)
                    ),
                    **recorded(PROBE_OTHER_KEY, 1, 32, selector_word(INVALID)),
                }
            ),
        }
    else:
        post = {
            owner: delegated_to(
                deployment.migrator, nonce=owner_nonce, storage=prior
            )
        }
    blockchain_test(pre=pre, blocks=blocks, post=post)


@pytest.mark.parametrize(
    "scope,magic",
    [
        pytest.param(SCOPE_PAYMENT, INVALID, id="payment_only"),
        pytest.param(SCOPE, ERC1271_MAGIC, id="execution"),
    ],
)
def test_is_valid_signature_scope(
    state_test: StateTestFiller,
    pre: Alloc,
    scope: int,
    magic: bytes,
) -> None:
    """
    Test R8's scope check on an account that already holds the kernel and
    one authority in its storage: a valid signature of that key gives
    `0xffffffff` when the scope is `0x1` (payment only), and the ERC-1271
    magic when it is `0x3` (the control).
    """
    verifier = pre.deploy_contract(verifier_code())
    account = pre.deploy_contract(
        KERNEL,
        storage={
            AUTHORITY_VERIFIER: int.from_bytes(verifier),
            AUTHORITY_SCOPE: scope,
            AUTHORITY_KEY_LENGTH: 64,
            AUTHORITY_KEY: int.from_bytes(NEW_KEY.public_key[:32]),
            AUTHORITY_KEY + 1: int.from_bytes(NEW_KEY.public_key[32:]),
        },
    )
    recorder = deploy_recorder(pre, 0)
    message = account_message_digest(CHAIN_ID, account, MESSAGE_HASH)
    tx = Transaction(
        sender=pre.fund_eoa(),
        to=recorder,
        data=record(
            0,
            account,
            is_valid_signature(MESSAGE_HASH, NEW_KEY.sign(message)),
        ),
        gas_limit=GAS_LIMIT,
    )
    state_test(
        pre=pre,
        tx=tx,
        post={
            recorder: Account(storage=recorded(0, 1, 32, selector_word(magic)))
        },
    )
