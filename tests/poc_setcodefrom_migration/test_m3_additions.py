"""
Tests added in M3 that need no spec decision: the raw ecrecover output of
an r = 0 signature, the "Completion" limit of the guard, a working prior
authority made void by the migration, and adopted code whose `initialize`
calls `finish` through the production Migrator.

The adopted code of the last test is a test-only tool from `harness.py`,
not reference implementation. Expectations branch on
`fork.is_eip_enabled(8151)`, so the same file fills on both trees.
"""

from dataclasses import replace
from typing import Dict

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Fork,
    Hash,
    Initcode,
    Storage,
    Transaction,
    TransactionReceipt,
    compute_create_address,
)

from ..eip8298_setcodefrom.spec import ref_spec_8298
from .contracts import (
    AUTHORITY_KEY,
    AUTHORITY_KEY_LENGTH,
    AUTHORITY_SCOPE,
    AUTHORITY_VERIFIER,
    ECRECOVER,
    ERC1271_MAGIC,
    FINISH,
    INITIALIZED_CODE_HASH_SLOT,
    INVALID,
    code_hash,
)
from .harness import tool_finish_calling_source_code
from .helpers import P256Key, account_message_digest, keccak, owner_signature
from .scenarios import (
    attempt,
    call_with_intent,
    delegated_to,
    kernel_hash,
    migrated_log,
    refusal_without_8151,
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
    deploy,
    deploy_recorder,
    ecrecover_input,
    intent,
    is_valid_signature,
    kernel_storage,
    migrate_calldata,
    record,
    recorded,
    registration,
    selector_word,
)
from .test_m2_guards import already_delegated_owner, authorize

REFERENCE_SPEC_GIT_PATH = ref_spec_8298.git_path
REFERENCE_SPEC_VERSION = ref_spec_8298.version

pytestmark = pytest.mark.valid_from("EIP8298")


def test_ecrecover_of_zero_r_signature(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Pin the premise of B3's `other_signature` on its own: ecrecover of a
    signature whose r is 0 (the owner's signature with r zeroed, as B3
    builds it) succeeds with empty output, with or without EIP-8151. So
    without the guard's link, P4 could pass on such a signature even
    without EIP-8151.
    """
    signer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    digest = keccak(b"setcodefrom poc m3 zero r")
    broken = bytes(32) + owner_signature(signer, digest)[32:]
    tx = Transaction(
        sender=pre.fund_eoa(),
        to=recorder,
        data=record(0, ECRECOVER, ecrecover_input(digest, broken)),
        gas_limit=GAS_LIMIT,
    )
    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[tx])],
        post={recorder: Account(storage=recorded(0, 1, 0, 0))},
    )


@with_form
def test_completion_with_skipped_authorization(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    Test the guard's "Completion" limit: completion is shown by `Migrated`,
    not by the transaction's success.

    The owner's EIP-7702 authorization to Migrator carries nonce 1 while
    the owner's nonce is 0, so it is skipped. `migrate` then hits the
    owner's empty code and "succeeds": status 1 and no log (no `Migrated`).
    The owner keeps empty code and nonce 0 (the authorization was skipped).
    Same with or without EIP-8151.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    executor = recorder if via_recorder else relayer
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    signature = owner_signature(owner, p.digest(CHAIN_ID, owner))
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(p, init, signature),
        via_recorder=via_recorder,
        reason=None,
        authorization=authorize(owner, deployment.migrator, nonce=1),
        logs=[],
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


def authority_storage(verifier: Address, key: P256Key) -> Dict[int, int]:
    """Return the kernel's slots of one authority: `key`, scope `0x3`."""
    return {
        AUTHORITY_VERIFIER: int.from_bytes(verifier),
        AUTHORITY_SCOPE: SCOPE,
        AUTHORITY_KEY_LENGTH: 64,
        AUTHORITY_KEY: int.from_bytes(key.public_key[:32]),
        AUTHORITY_KEY + 1: int.from_bytes(key.public_key[32:]),
    }


PROBE_CONTROL = 0x10
PROBE_NEW_KEY = 0x20
PROBE_OTHER_KEY = 0x30


def probe(
    sender: Address,
    recorder: Address,
    base: int,
    account: Address,
    key: P256Key,
) -> Transaction:
    """Return a transaction that records `account`'s ERC-1271 for `key`."""
    message = account_message_digest(CHAIN_ID, account, MESSAGE_HASH)
    return Transaction(
        sender=sender,
        to=recorder,
        data=record(
            base, account, is_valid_signature(MESSAGE_HASH, key.sign(message))
        ),
        gas_limit=GAS_LIMIT,
    )


@with_form
def test_prior_working_authority_void_after_migration(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    via_recorder: bool,
) -> None:
    """
    Test that a prior authority the kernel would accept stops working once
    the account migrates (R4: ignore authority data already in storage).

    The prior authority is `OTHER_KEY` (64-byte P256 key, scope `0x3`).
    Control: an account with the kernel's code and that storage gives the
    ERC-1271 magic for `OTHER_KEY`, so the prior authority is a working
    one. The owner is still delegated to an earlier delegate and holds the
    same storage. With EIP-8151 the migration installs `NEW_KEY`: every
    slot equals the new authority (no slot of the prior one is left),
    `OTHER_KEY` gives `0xffffffff` and `NEW_KEY` the magic. Without
    EIP-8151 the migration stops at P4 and the storage is untouched.
    """
    deployment = deploy(pre)
    prior = authority_storage(deployment.verifier, OTHER_KEY)
    control_storage = Storage()
    for slot, value in prior.items():
        control_storage[slot] = value
    control = pre.deploy_contract(KERNEL, storage=control_storage)
    owner = already_delegated_owner(pre, prior)
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    bases = [PROBE_CONTROL]
    adopted = fork.is_eip_enabled(8151)
    if adopted:
        bases += [PROBE_NEW_KEY, PROBE_OTHER_KEY]
    recorder = deploy_recorder(pre, *([0] if via_recorder else []), *bases)
    executor = recorder if via_recorder else relayer
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    digest = p.digest(CHAIN_ID, owner)
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(p, init, owner_signature(owner, digest)),
        via_recorder=via_recorder,
        reason=refusal_without_8151(fork),
        authorization=authorize(owner, deployment.migrator, nonce=1),
        logs=[migrated_log(deployment.check, owner, kernel_hash(), digest)],
    )
    probes = [probe(prober, recorder, PROBE_CONTROL, control, OTHER_KEY)]
    recorder_storage = {
        **run.recorder_post,
        **recorded(PROBE_CONTROL, 1, 32, selector_word(ERC1271_MAGIC)),
    }
    if adopted:
        probes += [
            probe(prober, recorder, PROBE_NEW_KEY, owner, NEW_KEY),
            probe(prober, recorder, PROBE_OTHER_KEY, owner, OTHER_KEY),
        ]
        recorder_storage.update(
            {
                **recorded(PROBE_NEW_KEY, 1, 32, selector_word(ERC1271_MAGIC)),
                **recorded(PROBE_OTHER_KEY, 1, 32, selector_word(INVALID)),
            }
        )
        owner_post = Account(
            code=KERNEL,
            nonce=2,
            storage=kernel_storage(deployment.verifier, NEW_KEY),
        )
    else:
        owner_post = delegated_to(deployment.migrator, nonce=2, storage=prior)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx]), Block(txs=probes)],
        post={
            **deployment.post(),
            owner: owner_post,
            control: Account(code=KERNEL, storage=prior),
            recorder: Account(storage=recorder_storage),
        },
    )


@with_form
@pytest.mark.parametrize(
    "calls_finish", [True, False], ids=["initialize_calls_finish", "control"]
)
def test_adopted_initialize_calls_finish(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    calls_finish: bool,
    via_recorder: bool,
) -> None:
    """
    Test Route A through the production Migrator and MigrationCheck when
    the adopted code's `initialize` calls `MigrationCheck.finish(p,
    ownerSig)` itself, as the account, and ignores the result (test-only
    code from `harness.py`). This checks v2.7's Route A details, "Linking
    `begin` and `finish`": `finish` consumes the (account, D) link.

    - `initialize_calls_finish`, with EIP-8151: the inner `finish` passes
      (and emits `Migrated`) and clears the mark, so Migrator's own
      `finish` reverts with `NotBegun` and the whole migration reverts.
      The owner stays delegated to Migrator.
    - `initialize_calls_finish`, without EIP-8151: Migrator's `finish`
      reverts with `P4Failed`, as in the control. This test does not
      observe the inner `finish` (by the code it reverts at P4, which
      rolls back its clearing of the mark).
    - `control`: `initialize` only writes R4's record and succeeds. With
      EIP-8151 the migration completes with one `Migrated`; without it,
      `P4Failed`.

    In both cases the test code's `initialize` writes R4's record first,
    so Migrator's check of the record (`NotInitialized`) passes and it is
    `finish` that decides.

    `initData` holds the address of a holder deployed in block 2, whose
    code is the calldata of `finish(p, ownerSig)`.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    executor = recorder if via_recorder else relayer
    source_code = tool_finish_calling_source_code(calls_finish=calls_finish)
    source = pre.deploy_contract(source_code)
    holder_deployer = pre.fund_eoa()
    holder = compute_create_address(address=holder_deployer, nonce=0)
    init = bytes(Hash(holder, left_padding=True))
    p = replace(
        intent(deployment, executor, init),
        source=source,
        code_hash=code_hash(source_code),
    )
    digest = p.digest(CHAIN_ID, owner)
    signature = owner_signature(owner, digest)
    holder_block = Block(
        txs=[
            Transaction(
                sender=holder_deployer,
                to=None,
                data=Initcode(
                    deploy_code=call_with_intent(FINISH, p, signature)
                ),
                gas_limit=GAS_LIMIT,
                expected_receipt=TransactionReceipt(status=1),
            )
        ]
    )
    if not fork.is_eip_enabled(8151):
        reason: str | None = "P4Failed"
    elif calls_finish:
        reason = "NotBegun"
    else:
        reason = None
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(p, init, signature),
        via_recorder=via_recorder,
        reason=reason,
        authorization=authorize(owner, deployment.migrator),
        logs=[
            migrated_log(
                deployment.check, owner, code_hash(source_code), digest
            )
        ],
    )
    if reason is None:
        # R4's record, written by the test code's `initialize`.
        owner_post = Account(
            code=source_code,
            nonce=1,
            storage={
                INITIALIZED_CODE_HASH_SLOT: int.from_bytes(
                    code_hash(source_code)
                )
            },
        )
    else:
        owner_post = delegated_to(deployment.migrator, nonce=1)
    post: Dict = {
        **deployment.post(),
        owner: owner_post,
        holder: Account(code=call_with_intent(FINISH, p, signature)),
    }
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, holder_block, Block(txs=[run.tx])],
        post=post,
    )
