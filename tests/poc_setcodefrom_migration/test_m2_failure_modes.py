"""
Reproduce the failure modes FM1 and FM3-FM6 of the pre-ERC adoption profile
with [EIP-8298: SETCODEFROM](https://eips.ethereum.org/EIPS/eip-8298), with
and without [EIP-8151](https://eips.ethereum.org/EIPS/eip-8151).

The bad examples, sources, fake ecrecover and stipend sender are test-only
tools from `harness.py`, not reference implementation. Expectations branch
on `fork.is_eip_enabled(8151)`, so the same file fills on both trees.
"""

from dataclasses import replace
from typing import Dict

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Fork,
    Header,
    Op,
    Transaction,
    TransactionException,
    TransactionReceipt,
)

from ...amsterdam.eip7708_eth_transfer_logs.spec import transfer_log
from ..eip8298_setcodefrom.helpers import (
    ADOPT_FROM_CALLDATA,
    RESULT_SLOT,
    SENTINEL,
    word,
)
from ..eip8298_setcodefrom.spec import ref_spec_8298
from .contracts import (
    ECRECOVER,
    ERC1271_MAGIC,
    INVALID,
    code_hash,
    delegation_indicator,
    error,
    verifier_code,
)
from .harness import (
    FAKE_EMPTY,
    FAKE_RETURN_OWNER,
    FAKE_REVERT,
    FAKE_REVERT_WITH_OWNER,
    FAKE_ZERO_WORD,
    bad_example_revert_everything_code,
    bad_example_self_recovery_wallet_code,
    tool_fake_ecrecover_code,
    tool_readopting_source_code,
    tool_self_replacing_source_code,
    tool_stipend_sender_code,
)
from .helpers import Migration, account_message_digest, keccak, owner_signature
from .scenarios import (
    attempt,
    check_post,
    delegated_to,
    deploy_with_ecrecover,
    initialize_calldata,
    kernel_hash,
    migrated_log,
    with_form,
)
from .test_m1_route_a import (
    CHAIN_ID,
    DEADLINE,
    GAS_LIMIT,
    HOOK_CALLS,
    KERNEL,
    MESSAGE_HASH,
    NEW_KEY,
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
    route_a_migration,
    selector_word,
)

REFERENCE_SPEC_GIT_PATH = ref_spec_8298.git_path
REFERENCE_SPEC_VERSION = ref_spec_8298.version

pytestmark = pytest.mark.valid_from("EIP8298")

SELF_RECOVERY_WALLET = bad_example_self_recovery_wallet_code()
REVERT_EVERYTHING = bad_example_revert_everything_code()
OWNER_BALANCE = 10**18
STIPEND_SENDER_BALANCE = 10


def delegation(owner: Address, relayer: Address, target: Address) -> Block:
    """Return a block whose only transaction delegates `owner` to `target`."""
    return Block(
        txs=[
            Transaction(
                sender=relayer,
                to=relayer,
                gas_limit=GAS_LIMIT,
                authorization_list=[
                    AuthorizationTuple(address=target, nonce=0, signer=owner)
                ],
            )
        ]
    )


def shell_adoption(
    pre: Alloc, owner: Address, relayer: Address, source: Address
) -> Block:
    """
    Return a block in which `owner` adopts `source`'s code through the
    simple adoption shell of M0 (`0x600035a760005500`): one type-4
    transaction, no initialization. The shell leaves 1 in the owner's slot 0.
    """
    shell = pre.deploy_contract(
        ADOPT_FROM_CALLDATA, storage={RESULT_SLOT: SENTINEL}
    )
    return Block(
        txs=[
            Transaction(
                sender=relayer,
                to=owner,
                data=word(source),
                gas_limit=GAS_LIMIT,
                authorization_list=[
                    AuthorizationTuple(address=shell, nonce=0, signer=owner)
                ],
                expected_receipt=TransactionReceipt(status=1),
            )
        ]
    )


# ---------------------------------------------------------------------------
# A1. FM1: self-recovery locks the account out
# ---------------------------------------------------------------------------


def test_fm1_self_recovery_while_delegated(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    A1a. Test that the self-recovering wallet accepts the old key while the
    owner only delegates to it with EIP-7702, with or without EIP-8151
    (EIP-8151 exempts delegation indicators).
    """
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    wallet = pre.deploy_contract(SELF_RECOVERY_WALLET)
    recorder = deploy_recorder(pre, 0)
    old_key_check = Transaction(
        sender=prober,
        to=recorder,
        data=record(
            0,
            owner,
            is_valid_signature(
                MESSAGE_HASH, owner_signature(owner, MESSAGE_HASH)
            ),
        ),
        gas_limit=GAS_LIMIT,
    )
    blockchain_test(
        pre=pre,
        blocks=[
            delegation(owner, relayer, wallet),
            Block(txs=[old_key_check]),
        ],
        post={
            owner: Account(code=delegation_indicator(wallet), nonce=1),
            recorder: Account(
                storage=recorded(0, 1, 32, selector_word(ERC1271_MAGIC))
            ),
        },
    )


def test_fm1_self_recovery_after_adoption(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    A1b. Test that once the owner adopts the self-recovering wallet (simple
    shell), the old key's signature no longer passes `isValidSignature`
    with EIP-8151 (lock-out), and still passes without it.
    """
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    wallet = pre.deploy_contract(SELF_RECOVERY_WALLET)
    recorder = deploy_recorder(pre, 0)
    old_key_check = Transaction(
        sender=prober,
        to=recorder,
        data=record(
            0,
            owner,
            is_valid_signature(
                MESSAGE_HASH, owner_signature(owner, MESSAGE_HASH)
            ),
        ),
        gas_limit=GAS_LIMIT,
    )
    answer = INVALID if fork.is_eip_enabled(8151) else ERC1271_MAGIC
    blockchain_test(
        pre=pre,
        blocks=[
            shell_adoption(pre, owner, relayer, wallet),
            Block(txs=[old_key_check]),
        ],
        post={
            owner: Account(
                code=SELF_RECOVERY_WALLET,
                nonce=1,
                storage={RESULT_SLOT: 1},
            ),
            recorder: Account(
                storage=recorded(0, 1, 32, selector_word(answer))
            ),
        },
    )


def test_fm1_guard_passes_self_recovery(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    A1c. Test that Route A migrates to the self-recovering wallet: the
    guard checks the signed inputs, not the code ("Limits of the guard").
    `Migrated` is emitted, and afterwards the old key's signature no longer
    passes `isValidSignature`. With EIP-8151 only.
    """
    if not fork.is_eip_enabled(8151):
        pytest.skip("without EIP-8151 the migration is refused at P4")
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    wallet = pre.deploy_contract(SELF_RECOVERY_WALLET)
    recorder = deploy_recorder(pre, 0)
    init = b"fm1: initialize does nothing"
    p = Migration(
        source=wallet,
        code_hash=code_hash(SELF_RECOVERY_WALLET),
        init_data_hash=keccak(init),
        deadline=DEADLINE,
        executor=relayer,
        check=deployment.check,
    )
    digest = p.digest(CHAIN_ID, owner)
    migration = Transaction(
        sender=relayer,
        to=owner,
        data=migrate_calldata(p, init, owner_signature(owner, digest)),
        gas_limit=GAS_LIMIT,
        authorization_list=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
        expected_receipt=TransactionReceipt(
            status=1,
            logs=[
                migrated_log(
                    deployment.check,
                    owner,
                    code_hash(SELF_RECOVERY_WALLET),
                    digest,
                )
            ],
        ),
    )
    old_key_check = Transaction(
        sender=prober,
        to=recorder,
        data=record(
            0,
            owner,
            is_valid_signature(
                MESSAGE_HASH, owner_signature(owner, MESSAGE_HASH)
            ),
        ),
        gas_limit=GAS_LIMIT,
    )
    blockchain_test(
        pre=pre,
        blocks=[
            deployment.block,
            Block(txs=[migration]),
            Block(txs=[old_key_check]),
        ],
        post={
            **deployment.post(),
            owner: Account(code=SELF_RECOVERY_WALLET, nonce=1, storage={}),
            recorder: Account(
                storage=recorded(0, 1, 32, selector_word(INVALID))
            ),
        },
    )


# ---------------------------------------------------------------------------
# A2. FM3: adopted but not initialized
# ---------------------------------------------------------------------------

PROBE_NEW_KEY = 0x10
PROBE_INITIALIZE = 0x20


def test_fm3_adopted_not_initialized(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    A2a. Test the reference kernel adopted through the simple shell, with
    no `initialize`: it holds no authority, so the new key's ERC-1271
    signature gives `0xffffffff`; `initialize` from outside reverts with
    `NotSelf`; and a new EIP-7702 authorization of the owner is skipped
    (the owner holds code), so nothing can make the account call itself.
    """
    verifier = pre.deploy_contract(verifier_code())
    template = pre.deploy_contract(KERNEL)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    recorder = deploy_recorder(pre, PROBE_NEW_KEY, PROBE_INITIALIZE)
    adoption = shell_adoption(pre, owner, relayer, template)
    init = registration(owner, verifier, NEW_KEY)
    message = account_message_digest(CHAIN_ID, owner, MESSAGE_HASH)
    probes = [
        Transaction(
            sender=prober,
            to=recorder,
            data=record(
                PROBE_NEW_KEY,
                owner,
                is_valid_signature(MESSAGE_HASH, NEW_KEY.sign(message)),
            ),
            gas_limit=GAS_LIMIT,
        ),
        Transaction(
            sender=prober,
            to=recorder,
            data=record(PROBE_INITIALIZE, owner, initialize_calldata(init)),
            gas_limit=GAS_LIMIT,
        ),
        # A delegation would be the only way to run code as the owner; the
        # authorization is skipped and the call reaches the kernel.
        Transaction(
            sender=relayer,
            to=owner,
            data=initialize_calldata(init),
            gas_limit=GAS_LIMIT,
            authorization_list=[
                AuthorizationTuple(address=recorder, nonce=1, signer=owner)
            ],
            expected_receipt=TransactionReceipt(status=0),
        ),
    ]
    blockchain_test(
        pre=pre,
        blocks=[adoption, Block(txs=probes)],
        post={
            # Nonce 1: the skipped authorization did not bump it.
            owner: Account(code=KERNEL, nonce=1, storage={RESULT_SLOT: 1}),
            recorder: Account(
                storage={
                    **recorded(PROBE_NEW_KEY, 1, 32, selector_word(INVALID)),
                    **recorded(
                        PROBE_INITIALIZE, 0, 4, selector_word(error("NotSelf"))
                    ),
                }
            ),
        },
    )


@pytest.mark.exception_test
def test_fm3_adopted_not_initialized_cannot_send(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    A2a. Test that the owner of the uninitialized kernel can no longer send
    a transaction with the old key (EIP-3607), with or without EIP-8151.
    """
    template = pre.deploy_contract(KERNEL)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    blockchain_test(
        pre=pre,
        blocks=[
            shell_adoption(pre, owner, relayer, template),
            Block(
                txs=[
                    Transaction(
                        sender=owner,
                        nonce=1,
                        to=owner,
                        data=initialize_calldata(b""),
                        error=TransactionException.SENDER_NOT_EOA,
                    )
                ],
                exception=TransactionException.SENDER_NOT_EOA,
            ),
        ],
        post={owner: Account(code=KERNEL, nonce=1, storage={RESULT_SLOT: 1})},
    )


# ---------------------------------------------------------------------------
# A3. FM4: receiving
# ---------------------------------------------------------------------------

PROBE_STIPEND = 0x70


def receive_probes(
    recorder: Address,
    prober: Address,
    stipend_sender: Address,
    owner: Address,
    *,
    receives: bool,
) -> list[Transaction]:
    """
    Return the receive probes against `owner`: plain ETH with empty
    calldata, the three token hooks (through the recorder) and 1 wei sent
    with a 0-gas `CALL` (the 2,300-gas stipend only).
    """
    eth = Transaction(
        sender=prober,
        to=owner,
        value=1,
        gas_limit=GAS_LIMIT,
        expected_receipt=TransactionReceipt(
            status=1, logs=[transfer_log(prober, owner, 1)]
        )
        if receives
        else TransactionReceipt(status=0, logs=[]),
    )
    hooks = [
        Transaction(
            sender=prober,
            to=recorder,
            data=record(base, owner, hook + args),
            gas_limit=GAS_LIMIT,
        )
        for base, hook, args in HOOK_CALLS
    ]
    stipend = Transaction(
        sender=prober,
        to=stipend_sender,
        data=word(owner) + word(Address(PROBE_STIPEND)),
        gas_limit=GAS_LIMIT,
    )
    return [eth, *hooks, stipend]


def hook_slots(*, receives: bool) -> Dict[int, int]:
    """Return the recorder slots of the three hook probes."""
    slots: Dict[int, int] = {}
    for base, hook, _ in HOOK_CALLS:
        if receives:
            slots.update(recorded(base, 1, 32, selector_word(hook)))
        else:
            slots.update(recorded(base, 0, 0, 0))
    return slots


def deploy_receive_tools(pre: Alloc) -> tuple[Address, Address]:
    """Deploy the recorder (hook slots) and the stipend sender."""
    recorder = deploy_recorder(pre, *(base for base, _, _ in HOOK_CALLS))
    stipend_sender = pre.deploy_contract(
        tool_stipend_sender_code(),
        balance=STIPEND_SENDER_BALANCE,
        storage={PROBE_STIPEND: SENTINEL},
    )
    return recorder, stipend_sender


def test_fm4_receive_with_migrator_delegation_left(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    A3a. Test that an account left delegated to Migrator by a failed
    migration receives plain ETH, the ERC-721/1155 hooks (each returns its
    selector) and 1 wei on the 2,300-gas stipend alone, with or without
    EIP-8151.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa(amount=OWNER_BALANCE)
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    recorder, stipend_sender = deploy_receive_tools(pre)
    # The signed code hash is not the source's: the migration reverts and
    # leaves the delegation.
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = replace(
        intent(deployment, relayer, init), code_hash=code_hash(Op.STOP)
    )
    failed = Transaction(
        sender=relayer,
        to=owner,
        data=migrate_calldata(
            p, init, owner_signature(owner, p.digest(CHAIN_ID, owner))
        ),
        gas_limit=GAS_LIMIT,
        authorization_list=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
        expected_receipt=TransactionReceipt(status=0, logs=[]),
    )
    blockchain_test(
        pre=pre,
        blocks=[
            deployment.block,
            Block(txs=[failed]),
            Block(
                txs=receive_probes(
                    recorder, prober, stipend_sender, owner, receives=True
                )
            ),
        ],
        post={
            owner: Account(
                code=delegation_indicator(deployment.migrator),
                nonce=1,
                balance=OWNER_BALANCE + 2,
                storage={},
            ),
            recorder: Account(storage=hook_slots(receives=True)),
            stipend_sender: Account(
                balance=STIPEND_SENDER_BALANCE - 1,
                storage={PROBE_STIPEND: 1},
            ),
        },
    )


def test_fm4_kernel_receives_on_stipend(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    A3b. Test that the migrated kernel receives 1 wei on the 2,300-gas
    stipend alone (R7's SHOULD). With EIP-8151 only.
    """
    if not fork.is_eip_enabled(8151):
        pytest.skip("without EIP-8151 the migration is refused at P4")
    deployment = deploy(pre)
    owner = pre.fund_eoa(amount=OWNER_BALANCE)
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    _, stipend_sender = deploy_receive_tools(pre)
    migration, _, _, owner_nonce = route_a_migration(
        deployment, owner, relayer, self_sent=False, adopted=True
    )
    stipend = Transaction(
        sender=prober,
        to=stipend_sender,
        data=word(owner) + word(Address(PROBE_STIPEND)),
        gas_limit=GAS_LIMIT,
    )
    blockchain_test(
        pre=pre,
        blocks=[
            deployment.block,
            Block(txs=[migration]),
            Block(txs=[stipend]),
        ],
        post={
            owner: Account(
                code=KERNEL,
                nonce=owner_nonce,
                balance=OWNER_BALANCE + 1,
                storage=kernel_storage(deployment.verifier, NEW_KEY),
            ),
            stipend_sender: Account(
                balance=STIPEND_SENDER_BALANCE - 1,
                storage={PROBE_STIPEND: 1},
            ),
        },
    )


def test_fm4_code_without_receive_path(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    A3c. Test that code with no receive path (it reverts on every call),
    adopted through the simple shell, makes plain ETH, the stipend send
    and the token hooks fail, with or without EIP-8151.
    """
    owner = pre.fund_eoa(amount=OWNER_BALANCE)
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    source = pre.deploy_contract(REVERT_EVERYTHING)
    recorder, stipend_sender = deploy_receive_tools(pre)
    blockchain_test(
        pre=pre,
        blocks=[
            shell_adoption(pre, owner, relayer, source),
            Block(
                txs=receive_probes(
                    recorder, prober, stipend_sender, owner, receives=False
                )
            ),
        ],
        post={
            owner: Account(
                code=REVERT_EVERYTHING,
                nonce=1,
                balance=OWNER_BALANCE,
                storage={RESULT_SLOT: 1},
            ),
            # Each hook call reverts with no data, so a token contract's
            # check of the returned selector fails.
            recorder: Account(storage=hook_slots(receives=False)),
            stipend_sender: Account(
                balance=STIPEND_SENDER_BALANCE,
                storage={PROBE_STIPEND: 0},
            ),
        },
    )


# ---------------------------------------------------------------------------
# A4. FM5: the source can change
# ---------------------------------------------------------------------------


@with_form
def test_fm5_source_replaced_after_signing(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    A4a. Test that the source replacing its own code between the signature
    and the execution makes the migration revert with `SourceHashMismatch`:
    block 2 replaces the source, block 3 runs the intent signed over the
    original code hash.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    original = tool_self_replacing_source_code()
    replacement_code = Op.INVALID
    source = pre.deploy_contract(original)
    replacement = pre.deploy_contract(replacement_code)
    executor = recorder if via_recorder else relayer
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = replace(
        intent(deployment, executor, init),
        source=source,
        code_hash=code_hash(original),
    )
    replace_source = Transaction(
        sender=relayer,
        to=source,
        data=word(replacement),
        gas_limit=GAS_LIMIT,
        expected_receipt=TransactionReceipt(status=1),
    )
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(
            p, init, owner_signature(owner, p.digest(CHAIN_ID, owner))
        ),
        via_recorder=via_recorder,
        reason="SourceHashMismatch",
        authorization=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
    )
    post = {
        **deployment.post(),
        source: Account(code=replacement_code),
        owner: delegated_to(deployment.migrator, nonce=1),
    }
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[
            deployment.block,
            Block(txs=[replace_source]),
            Block(txs=[run.tx]),
        ],
        post=post,
    )


@with_form
def test_fm5_adopted_code_replaces_itself(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    A4b. Test a source whose `initialize` replaces the account's code with
    other code: Migrator's checks before adoption pass, and `finish` stops
    the migration at P2 (`P2Failed`), with or without EIP-8151.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    other = pre.deploy_contract(Op.STOP)
    readopting = tool_readopting_source_code(other)
    source = pre.deploy_contract(readopting)
    executor = recorder if via_recorder else relayer
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = replace(
        intent(deployment, executor, init),
        source=source,
        code_hash=code_hash(readopting),
    )
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(
            p, init, owner_signature(owner, p.digest(CHAIN_ID, owner))
        ),
        via_recorder=via_recorder,
        reason="P2Failed",
        authorization=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
    )
    post = {
        **deployment.post(),
        source: Account(code=readopting),
        owner: delegated_to(deployment.migrator, nonce=1),
    }
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post=post,
    )


@with_form
def test_fm5_setcodefrom_fails_on_delegated_source(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    A4c. Test a source that is an EIP-7702-delegated EOA (its code starts
    with `0xEF`), signed with the hash of its delegation indicator:
    Migrator's hash check passes, `SETCODEFROM` returns 0 and the
    migration reverts with `SetCodeFailed`, with or without EIP-8151.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    source = pre.fund_eoa(delegation=deployment.template)
    executor = recorder if via_recorder else relayer
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = replace(
        intent(deployment, executor, init),
        source=source,
        code_hash=keccak(delegation_indicator(deployment.template)),
    )
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(
            p, init, owner_signature(owner, p.digest(CHAIN_ID, owner))
        ),
        via_recorder=via_recorder,
        reason="SetCodeFailed",
        authorization=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
    )
    post = {
        **deployment.post(),
        source: Account(code=delegation_indicator(deployment.template)),
        owner: delegated_to(deployment.migrator, nonce=1),
    }
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post=post,
    )


# ---------------------------------------------------------------------------
# A5. FM6: an empty ecrecover result proves nothing
# ---------------------------------------------------------------------------


@with_form
def test_fm6_p1_refuses_other_signer_without_code(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    via_recorder: bool,
) -> None:
    """
    A5a. Test that `D` signed by another key, whose address holds no code,
    is refused at P1 (`P1Failed`), with or without EIP-8151.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    other = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    executor = recorder if via_recorder else relayer
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    run = attempt(
        sender=relayer,
        owner=owner,
        recorder=recorder,
        calldata=migrate_calldata(
            p, init, owner_signature(other, p.digest(CHAIN_ID, owner))
        ),
        via_recorder=via_recorder,
        reason="P1Failed",
        authorization=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
    )
    post = {
        **deployment.post(),
        owner: delegated_to(deployment.migrator, nonce=1),
        other: Account(code=b"", nonce=0),
    }
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post=post,
    )


@pytest.mark.pre_alloc_mutable
def test_fm6_ecrecover_of_signer_with_code(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    A5b. Test the premise of M1's case 8b on its own: for a signer whose
    address holds code, ecrecover returns empty output with EIP-8151 and
    the signer's address without it.
    """
    signer = pre.fund_eoa(code=Op.STOP)
    recorder = deploy_recorder(pre, 0)
    digest = keccak(b"setcodefrom poc m2 signer with code")
    signature = owner_signature(signer, digest)
    tx = Transaction(
        sender=pre.fund_eoa(),
        to=recorder,
        data=record(0, ECRECOVER, ecrecover_input(digest, signature)),
        gas_limit=GAS_LIMIT,
    )
    if fork.is_eip_enabled(8151):
        outcome = recorded(0, 1, 0, 0)
    else:
        outcome = recorded(0, 1, 32, int.from_bytes(signer))
    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[tx])],
        post={
            signer: Account(code=Op.STOP),
            recorder: Account(storage=outcome),
        },
    )


# case: (while delegated, otherwise, expected reason or None)
FAKE_ECRECOVER_CASES = {
    "zero_word": (FAKE_RETURN_OWNER, FAKE_ZERO_WORD, "P4Failed"),
    "empty_output": (FAKE_RETURN_OWNER, FAKE_EMPTY, None),
    "p4_call_reverts": (FAKE_RETURN_OWNER, FAKE_REVERT, "P4Failed"),
    "p1_reverts_with_owner": (FAKE_REVERT_WITH_OWNER, FAKE_EMPTY, "P1Failed"),
}


@with_form
@pytest.mark.parametrize("case", list(FAKE_ECRECOVER_CASES))
def test_fm6_p1_p4_against_fake_ecrecover(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    case: str,
    via_recorder: bool,
) -> None:
    """
    A5c. Test P1 and P4 against a fake ecrecover (TEST ONLY), with a
    `MigrationCheck` and Migrator bound to it. The fake ignores EIP-8151,
    so both trees give the same result.

    - `zero_word`: owner while delegated, then 32 zero bytes: `P4Failed`.
    - `empty_output` (the control): owner, then empty output: migrates.
    - `p4_call_reverts`: owner, then a revert with no data: `P4Failed`
      (P4 checks `success`, not only `returndatasize`).
    - `p1_reverts_with_owner`: a revert whose 32-byte data is the owner:
      `P1Failed` (P1 checks `success`, not only the output).
    """
    while_delegated, otherwise, reason = FAKE_ECRECOVER_CASES[case]
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    fake = pre.deploy_contract(
        tool_fake_ecrecover_code(
            owner, while_delegated=while_delegated, otherwise=otherwise
        )
    )
    deployment = deploy_with_ecrecover(pre, fake)
    recorder = deploy_recorder(pre, 0)
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
        reason=reason,
        authorization=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
        logs=[migrated_log(deployment.check, owner, kernel_hash(), digest)],
    )
    post: Dict = {**check_post(deployment, fake)}
    if reason is not None:
        post[owner] = delegated_to(deployment.migrator, nonce=1)
    else:
        post[owner] = Account(
            code=KERNEL,
            nonce=1,
            storage=kernel_storage(deployment.verifier, NEW_KEY),
        )
    if via_recorder:
        post[recorder] = Account(storage=run.recorder_post)
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[run.tx])],
        post=post,
    )


PLAIN_TRANSFER_GAS = 21_000


@pytest.mark.parametrize(
    "target,received",
    [
        pytest.param("eoa", True, id="eoa"),
        pytest.param("migrator_delegated", False, id="migrator_delegated"),
        pytest.param("kernel_adopted", False, id="kernel_adopted"),
    ],
)
def test_fm4_plain_transfer_with_21000_gas(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    target: str,
    received: bool,
) -> None:
    """
    A3d. Test a plain 1-wei transfer with a 21,000 gas limit to an EOA
    without code, an account delegated to Migrator, and an account that
    adopted the kernel (simple shell).

    Observed, not decided beforehand: here the intrinsic gas of the
    transfer is exactly 21,000 (EIP-2780: TX_BASE 12,000 + cold recipient
    3,000 + value 6,000), so the frame starts with 0 gas. The EOA receives;
    the delegated account fails on the cold access to the delegate and the
    kernel on its first opcode: status 0, the whole 21,000 is used, and
    the 1 wei stays with the sender. Same with or without EIP-8151.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa(amount=OWNER_BALANCE)
    relayer = pre.fund_eoa()
    sender = pre.fund_eoa()
    blocks = [deployment.block]
    code = b""
    if target == "migrator_delegated":
        blocks.append(delegation(owner, relayer, deployment.migrator))
        code = delegation_indicator(deployment.migrator)
    elif target == "kernel_adopted":
        blocks.append(shell_adoption(pre, owner, relayer, deployment.template))
        code = bytes(KERNEL)
    transfer = Transaction(
        sender=sender,
        to=owner,
        value=1,
        gas_limit=PLAIN_TRANSFER_GAS,
        expected_receipt=TransactionReceipt(
            status=1 if received else 0,
            cumulative_gas_used=PLAIN_TRANSFER_GAS,
        ),
    )
    blocks.append(Block(txs=[transfer], header_verify=Header(gas_used=21_000)))
    blockchain_test(
        pre=pre,
        blocks=blocks,
        post={
            owner: Account(
                code=code, balance=OWNER_BALANCE + (1 if received else 0)
            )
        },
    )
