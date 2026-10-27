"""
Test Route A of the pre-ERC adoption profile end to end: an EOA delegates to
`Migrator` with EIP-7702 and calls `migrate`, which adopts the reference
kernel via [EIP-8298: SETCODEFROM](https://eips.ethereum.org/EIPS/eip-8298)
between `MigrationCheck.begin` (P1) and `.finish` (P2, P4).

With [EIP-8151](https://eips.ethereum.org/EIPS/eip-8151) the migration
completes; without it, P4 refuses it. The expectations branch on
`fork.is_eip_enabled(8151)`, so the same file fills on both trees.

The kernel here is not conforming code: this tree has no EIP-8141, so it
has no `VERIFY` (R2) and no relay path.
"""

from dataclasses import dataclass, replace
from typing import Dict

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
    Bytecode,
    Fork,
    Hash,
    Initcode,
    Op,
    StateTestFiller,
    Storage,
    Transaction,
    TransactionException,
    TransactionLog,
    TransactionReceipt,
    compute_create_address,
)
from execution_testing.test_types import ChainConfigDefaults

from ...amsterdam.eip7708_eth_transfer_logs.spec import transfer_log
from ..eip8298_setcodefrom.helpers import SENTINEL
from ..eip8298_setcodefrom.spec import ref_spec_8298
from .contracts import (
    AUTHORITY_KEY,
    AUTHORITY_KEY_LENGTH,
    AUTHORITY_SCOPE,
    AUTHORITY_VERIFIER,
    ECRECOVER,
    ERC1271_MAGIC,
    INITIALIZE,
    INITIALIZED_CODE_HASH_SLOT,
    INVALID,
    IS_VALID_SIGNATURE,
    MIGRATE,
    MIGRATED_TOPIC,
    ON_ERC721_RECEIVED,
    ON_ERC1155_BATCH_RECEIVED,
    ON_ERC1155_RECEIVED,
    RETURN_WORD,
    RETURNDATASIZE,
    ROUTE_A,
    SUCCESS,
    VERIFIER_MAGIC,
    VERIFY,
    code_hash,
    delegation_indicator,
    error,
    kernel_code,
    migration_check_code,
    migrator_code,
    recorder_code,
    verifier_code,
)
from .harness import bad_example_permissive_fallback_code
from .helpers import (
    MIGRATION_TUPLE,
    SCOPE_EXECUTION,
    SCOPE_PAYMENT,
    Migration,
    P256Key,
    account_message_digest,
    init_data,
    keccak,
    owner_signature,
    registration_digest,
)

REFERENCE_SPEC_GIT_PATH = ref_spec_8298.git_path
REFERENCE_SPEC_VERSION = ref_spec_8298.version

pytestmark = pytest.mark.valid_from("EIP8298")

CHAIN_ID = ChainConfigDefaults.chain_id
DEADLINE = 0xFFFF_FFFF
GAS_LIMIT = 10_000_000
SCOPE = SCOPE_PAYMENT | SCOPE_EXECUTION
NEW_KEY = P256Key(0xC0FFEE)
OTHER_KEY = P256Key(0xBADC0DE)
MESSAGE_HASH = keccak(b"setcodefrom poc m1 message")
KERNEL = kernel_code()


@dataclass(frozen=True)
class Deployment:
    """The PoC contracts, with the block that deploys Migrator and Check."""

    verifier: Address
    template: Address
    migrator: Address
    check: Address
    block: Block

    def post(self) -> Dict[Address, Account]:
        """Return the deployed code of Migrator and MigrationCheck."""
        return {
            self.migrator: Account(
                code=migrator_code(self.migrator, self.check)
            ),
            self.check: Account(code=migration_check_code(self.migrator)),
        }


def deploy(pre: Alloc) -> Deployment:
    """
    Deploy the verifier and the inert kernel template in the pre-state, and
    return a block in which a deployer EOA creates Migrator and
    MigrationCheck, whose addresses are computed beforehand because each
    holds the other's (and Migrator its own) as a constant.
    """
    verifier = pre.deploy_contract(verifier_code())
    template = pre.deploy_contract(KERNEL)
    deployer = pre.fund_eoa()
    migrator = compute_create_address(address=deployer, nonce=0)
    check = compute_create_address(address=deployer, nonce=1)
    block = Block(
        txs=[
            Transaction(
                sender=deployer,
                nonce=0,
                to=None,
                data=Initcode(deploy_code=migrator_code(migrator, check)),
                gas_limit=GAS_LIMIT,
                expected_receipt=TransactionReceipt(status=1),
            ),
            Transaction(
                sender=deployer,
                nonce=1,
                to=None,
                data=Initcode(deploy_code=migration_check_code(migrator)),
                gas_limit=GAS_LIMIT,
                expected_receipt=TransactionReceipt(status=1),
            ),
        ]
    )
    return Deployment(verifier, template, migrator, check, block)


def registration(
    account: Address,
    verifier: Address,
    key: P256Key,
    *,
    prover: P256Key | None = None,
) -> bytes:
    """
    Return `initData` that registers `key`, with its registration proof
    signed by `prover` (by default, the key itself).
    """
    digest = registration_digest(
        CHAIN_ID, account, verifier, key.public_key, SCOPE
    )
    proof = (prover or key).sign(digest)
    return init_data(verifier, key.public_key, SCOPE, proof)


def intent(
    deployment: Deployment, executor: Address, init: bytes
) -> Migration:
    """Return a `Migration` that adopts the template and runs `init`."""
    return Migration(
        source=deployment.template,
        code_hash=code_hash(KERNEL),
        init_data_hash=keccak(init),
        deadline=DEADLINE,
        executor=executor,
        check=deployment.check,
    )


def migrate_calldata(p: Migration, init: bytes, signature: bytes) -> bytes:
    """Return the calldata of `migrate(p, initData, ownerSig)`."""
    return MIGRATE + encode(
        [MIGRATION_TUPLE, "bytes", "bytes"], [p.abi_tuple(), init, signature]
    )


def migrated_log(
    deployment: Deployment, account: Address, digest: Hash
) -> TransactionLog:
    """Return the `Migrated(account, codeHash, D, route)` log of Route A."""
    return TransactionLog(
        address=deployment.check,
        topics=[
            MIGRATED_TOPIC,
            Hash(account, left_padding=True),
            code_hash(KERNEL),
        ],
        data=bytes(digest) + ROUTE_A.to_bytes(32, "big"),
    )


def kernel_storage(verifier: Address, key: P256Key) -> Dict[int, int]:
    """Return the kernel's storage after it installed `key`."""
    return {
        AUTHORITY_VERIFIER: int.from_bytes(verifier),
        AUTHORITY_SCOPE: SCOPE,
        AUTHORITY_KEY_LENGTH: 64,
        AUTHORITY_KEY: int.from_bytes(key.public_key[:32]),
        AUTHORITY_KEY + 1: int.from_bytes(key.public_key[32:]),
        INITIALIZED_CODE_HASH_SLOT: int.from_bytes(code_hash(KERNEL)),
    }


def record(base: int, target: Address, payload: bytes) -> bytes:
    """Return calldata that makes the recorder call `target`."""
    return Hash(base) + Hash(target, left_padding=True) + payload


def recorded(base: int, success: int, size: int, word: int) -> Dict[int, int]:
    """Return the recorder slots of one call."""
    return {
        base + SUCCESS: success,
        base + RETURNDATASIZE: size,
        base + RETURN_WORD: word,
    }


def deploy_recorder(pre: Alloc, *bases: int) -> Address:
    """Deploy the recorder with its slots at `bases` pre-set to SENTINEL."""
    storage = Storage()
    for base in bases:
        for offset in (SUCCESS, RETURNDATASIZE, RETURN_WORD):
            storage[base + offset] = SENTINEL
    return pre.deploy_contract(recorder_code(), storage=storage)


def selector_word(value: bytes) -> int:
    """Return `value` left-aligned in a word, as ABI encodes `bytes4`."""
    return int.from_bytes(value) << 224


def ecrecover_input(digest: Hash, signature: bytes) -> bytes:
    """Return the ecrecover input `D ‖ v ‖ r ‖ s` of a 65-byte signature."""
    return (
        bytes(digest)
        + signature[64].to_bytes(32, "big")
        + signature[0:32]
        + signature[32:64]
    )


def is_valid_signature(message_hash: Hash, signature: bytes) -> bytes:
    """Return the calldata of `isValidSignature(hash, signature)`."""
    return IS_VALID_SIGNATURE + encode(
        ["bytes32", "bytes"], [bytes(message_hash), signature]
    )


# Recorder slots of the post-migration probes.
PROBE_ECRECOVER = 0x10
PROBE_NEW_KEY = 0x20
PROBE_OLD_KEY = 0x30
PROBE_ERC721 = 0x40
PROBE_ERC1155 = 0x50
PROBE_ERC1155_BATCH = 0x60
PROBES = (
    PROBE_ECRECOVER,
    PROBE_NEW_KEY,
    PROBE_OLD_KEY,
    PROBE_ERC721,
    PROBE_ERC1155,
    PROBE_ERC1155_BATCH,
)

HOOK_CALLS = [
    (
        PROBE_ERC721,
        ON_ERC721_RECEIVED,
        encode(
            ["address", "address", "uint256", "bytes"],
            ["0x" + "11" * 20, "0x" + "22" * 20, 1, b""],
        ),
    ),
    (
        PROBE_ERC1155,
        ON_ERC1155_RECEIVED,
        encode(
            ["address", "address", "uint256", "uint256", "bytes"],
            ["0x" + "11" * 20, "0x" + "22" * 20, 1, 1, b""],
        ),
    ),
    (
        PROBE_ERC1155_BATCH,
        ON_ERC1155_BATCH_RECEIVED,
        encode(
            ["address", "address", "uint256[]", "uint256[]", "bytes"],
            ["0x" + "11" * 20, "0x" + "22" * 20, [1], [1], b""],
        ),
    ),
]


def route_a_migration(
    deployment: Deployment,
    owner: EOA,
    relayer: EOA,
    *,
    self_sent: bool,
    adopted: bool,
) -> tuple[Transaction, Hash, bytes, int]:
    """
    Return the type-4 transaction that delegates `owner` to Migrator and
    calls `migrate` (sent by the owner or by `relayer`), with `D`, ownerSig
    and the owner's nonce after it.
    """
    executor = owner if self_sent else relayer
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, init)
    digest = p.digest(CHAIN_ID, owner)
    signature = owner_signature(owner, digest)
    if self_sent:
        # The sender's nonce is taken first, so the authorization uses 1.
        auth_nonce, sender_nonce = 1, {"nonce": 0}
    else:
        auth_nonce, sender_nonce = 0, {}
    migration = Transaction(
        sender=executor,
        to=owner,
        data=migrate_calldata(p, init, signature),
        gas_limit=GAS_LIMIT,
        authorization_list=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=auth_nonce, signer=owner
            )
        ],
        expected_receipt=TransactionReceipt(
            status=1 if adopted else 0,
            logs=[migrated_log(deployment, owner, digest)] if adopted else [],
        ),
        **sender_nonce,
    )
    return migration, digest, signature, auth_nonce + 1


with_self_sent = pytest.mark.parametrize(
    "self_sent",
    [
        pytest.param(True, id="self_sent"),
        pytest.param(False, id="sponsored"),
    ],
)


@with_self_sent
def test_route_a_migration(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    self_sent: bool,
) -> None:
    """
    Test one type-4 transaction that delegates the owner to Migrator and
    calls `migrate`, sent by the owner itself or by a sponsor.

    With EIP-8151 the kernel is adopted and initialized and `Migrated` is
    emitted; afterwards the old key no longer passes ecrecover, the new
    P256 key passes ERC-1271 and the old key does not, and the account
    receives ETH and token hooks. Without EIP-8151 the whole transaction
    reverts at P4, the delegation stays, and the old key still recovers
    and sends.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    prober = pre.fund_eoa()
    recorder = deploy_recorder(pre, *PROBES)
    adopted = fork.is_eip_enabled(8151)
    migration, digest, signature, owner_nonce = route_a_migration(
        deployment, owner, relayer, self_sent=self_sent, adopted=adopted
    )

    probe_ecrecover = Transaction(
        sender=prober,
        to=recorder,
        data=record(
            PROBE_ECRECOVER, ECRECOVER, ecrecover_input(digest, signature)
        ),
        gas_limit=GAS_LIMIT,
    )
    blocks = [deployment.block, Block(txs=[migration])]
    storage: Dict[int, int] = {
        base + offset: SENTINEL
        for base in PROBES
        for offset in (SUCCESS, RETURNDATASIZE, RETURN_WORD)
    }

    if adopted:
        message = account_message_digest(CHAIN_ID, owner, MESSAGE_HASH)
        probes = [
            probe_ecrecover,
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
                data=record(
                    PROBE_OLD_KEY,
                    owner,
                    is_valid_signature(
                        MESSAGE_HASH, owner_signature(owner, message)
                    ),
                ),
                gas_limit=GAS_LIMIT,
            ),
            *(
                Transaction(
                    sender=prober,
                    to=recorder,
                    data=record(base, owner, hook + args),
                    gas_limit=GAS_LIMIT,
                )
                for base, hook, args in HOOK_CALLS
            ),
            # R7: plain ETH with empty calldata.
            Transaction(
                sender=prober,
                to=owner,
                value=1,
                gas_limit=GAS_LIMIT,
                expected_receipt=TransactionReceipt(
                    status=1, logs=[transfer_log(prober, owner, 1)]
                ),
            ),
        ]
        storage.update(
            {
                # Withheld: a successful call with empty output.
                **recorded(PROBE_ECRECOVER, 1, 0, 0),
                **recorded(PROBE_NEW_KEY, 1, 32, selector_word(ERC1271_MAGIC)),
                # R1: the old key is no authority of the kernel.
                **recorded(PROBE_OLD_KEY, 1, 32, selector_word(INVALID)),
                **{
                    key: value
                    for base, hook, _ in HOOK_CALLS
                    for key, value in recorded(
                        base, 1, 32, selector_word(hook)
                    ).items()
                },
            }
        )
        blocks += [Block(txs=probes)]
        owner_post = Account(
            code=KERNEL,
            nonce=owner_nonce,
            storage=kernel_storage(deployment.verifier, NEW_KEY),
        )
    else:
        storage.update(recorded(PROBE_ECRECOVER, 1, 32, int.from_bytes(owner)))
        # Nothing was adopted, so the old key still sends.
        old_key_send = Transaction(
            sender=owner, nonce=owner_nonce, to=prober, value=1
        )
        blocks += [Block(txs=[probe_ecrecover, old_key_send])]
        owner_post = Account(
            code=delegation_indicator(deployment.migrator),
            nonce=owner_nonce + 1,
            storage={},
        )

    blockchain_test(
        pre=pre,
        blocks=blocks,
        post={
            **deployment.post(),
            owner: owner_post,
            recorder: Account(storage=storage),
            deployment.template: Account(code=KERNEL, storage={}),
        },
    )


@pytest.mark.exception_test
@with_self_sent
def test_old_key_rejected_after_migration(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    self_sent: bool,
) -> None:
    """
    Test that after the migration the old key can no longer send a
    transaction (EIP-3607), in the block after it.

    Only with EIP-8151: without it nothing is adopted, and
    `test_route_a_migration` shows the old key still sends.
    """
    if not fork.is_eip_enabled(8151):
        pytest.skip("without EIP-8151 the migration is refused at P4")
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    migration, _, _, owner_nonce = route_a_migration(
        deployment, owner, relayer, self_sent=self_sent, adopted=True
    )
    old_key_send = Transaction(
        sender=owner,
        nonce=owner_nonce,
        to=relayer,
        value=1,
        error=TransactionException.SENDER_NOT_EOA,
    )
    blockchain_test(
        pre=pre,
        blocks=[
            deployment.block,
            Block(txs=[migration]),
            Block(
                txs=[old_key_send],
                exception=TransactionException.SENDER_NOT_EOA,
            ),
        ],
        post={
            owner: Account(
                code=KERNEL,
                nonce=owner_nonce,
                storage=kernel_storage(deployment.verifier, NEW_KEY),
            )
        },
    )


def test_p1_while_delegated(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that ecrecover still returns an owner that only holds a delegation
    indicator, with or without EIP-8151, as P1 in Route A needs.
    """
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    delegate = pre.deploy_contract(Op.STOP)
    recorder = deploy_recorder(pre, PROBE_ECRECOVER)
    digest = keccak(b"setcodefrom poc m1 delegated digest")
    signature = owner_signature(owner, digest)

    delegation = Transaction(
        sender=relayer,
        to=relayer,
        gas_limit=GAS_LIMIT,
        authorization_list=[
            AuthorizationTuple(address=delegate, nonce=0, signer=owner)
        ],
    )
    probe = Transaction(
        sender=relayer,
        to=recorder,
        data=record(
            PROBE_ECRECOVER, ECRECOVER, ecrecover_input(digest, signature)
        ),
        gas_limit=GAS_LIMIT,
    )
    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[delegation]), Block(txs=[probe])],
        post={
            owner: Account(code=delegation_indicator(delegate), nonce=1),
            recorder: Account(
                storage=recorded(PROBE_ECRECOVER, 1, 32, int.from_bytes(owner))
            ),
        },
    )


def test_template_is_inert(
    state_test: StateTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that the deployed template rejects `initialize` from outside, even
    with a valid registration proof bound to the template's address.
    """
    verifier = pre.deploy_contract(verifier_code())
    template = pre.deploy_contract(KERNEL)
    recorder = deploy_recorder(pre, 0)
    init = registration(template, verifier, NEW_KEY)
    tx = Transaction(
        sender=pre.fund_eoa(),
        to=recorder,
        data=record(0, template, INITIALIZE + encode(["bytes"], [init])),
        gas_limit=GAS_LIMIT,
    )
    state_test(
        pre=pre,
        tx=tx,
        post={
            template: Account(code=KERNEL, storage={}),
            recorder: Account(
                storage=recorded(0, 0, 4, selector_word(error("NotSelf")))
            ),
        },
    )


@dataclass(frozen=True)
class Rejection:
    """A broken migration and the check that must refuse it."""

    reason: str


REJECTIONS = {
    # 7: the signed code hash is not the source's.
    "code_hash_mismatch": Rejection("SourceHashMismatch"),
    # 8a: r = 0, so ecrecover returns empty output before adoption too.
    "broken_owner_signature": Rejection("P1Failed"),
    # 8b: another key, whose address holds code, signed D.
    "other_signer_with_code": Rejection("P1Failed"),
    # 9: the executor passes other initData than the owner signed.
    "init_data_swapped": Rejection("InitDataMismatch"),
    # 10: the registration proof is not the key's, so initialize reverts.
    "bad_registration_proof": Rejection("InitializeFailed"),
    # 11: initialize "succeeds" because the code's fallback accepts every
    # selector, but nothing ran and R4's record is empty (a v2.8 candidate:
    # v2.7's P3 only looks at whether the call reverted).
    "initialize_not_recorded": Rejection("NotInitialized"),
}


@pytest.mark.parametrize(
    "via_recorder", [False, True], ids=["direct", "recorded"]
)
@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            case,
            id=case,
            # An EOA with code needs a mutable pre-state.
            marks=[pytest.mark.pre_alloc_mutable]
            if case == "other_signer_with_code"
            else [],
        )
        for case in REJECTIONS
    ],
)
def test_route_a_rejected(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    case: str,
    via_recorder: bool,
) -> None:
    """
    Test that a broken migration reverts as a whole, with or without
    EIP-8151: nothing is adopted, no `Migrated` is emitted, and the 7702
    delegation stays.

    `direct` sends it from a sponsor as in Route A. `recorded` names the
    recorder as executor and records which check reverted.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    executor = recorder if via_recorder else relayer

    signed_init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, executor, signed_init)
    sent_init = signed_init
    if case == "code_hash_mismatch":
        p = replace(p, code_hash=code_hash(Op.STOP))
    elif case == "initialize_not_recorded":
        permissive = bad_example_permissive_fallback_code()
        p = replace(
            p,
            source=pre.deploy_contract(permissive),
            code_hash=code_hash(permissive),
        )
    elif case == "init_data_swapped":
        sent_init = registration(owner, deployment.verifier, OTHER_KEY)
    elif case == "bad_registration_proof":
        sent_init = registration(
            owner, deployment.verifier, NEW_KEY, prover=OTHER_KEY
        )
        p = intent(deployment, executor, sent_init)

    digest = p.digest(CHAIN_ID, owner)
    if case == "broken_owner_signature":
        signature = bytes(32) + owner_signature(owner, digest)[32:]
    elif case == "other_signer_with_code":
        other = pre.fund_eoa(code=Op.STOP)
        signature = owner_signature(other, digest)
    else:
        signature = owner_signature(owner, digest)

    calldata = migrate_calldata(p, sent_init, signature)
    authorization = [
        AuthorizationTuple(address=deployment.migrator, nonce=0, signer=owner)
    ]
    post: Dict[Address, Account] = {
        **deployment.post(),
        owner: Account(
            code=delegation_indicator(deployment.migrator),
            nonce=1,
            storage={},
        ),
    }
    if via_recorder:
        tx = Transaction(
            sender=relayer,
            to=recorder,
            data=record(0, owner, calldata),
            gas_limit=GAS_LIMIT,
            authorization_list=authorization,
            expected_receipt=TransactionReceipt(status=1, logs=[]),
        )
        post[recorder] = Account(
            storage=recorded(
                0, 0, 4, selector_word(error(REJECTIONS[case].reason))
            )
        )
    else:
        tx = Transaction(
            sender=relayer,
            to=owner,
            data=calldata,
            gas_limit=GAS_LIMIT,
            authorization_list=authorization,
            expected_receipt=TransactionReceipt(status=0, logs=[]),
        )

    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[tx])],
        post=post,
    )


def test_route_a_refusal_reason(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test which check decides a valid migration, with the recorder as
    executor: it completes with EIP-8151 and reverts with `P4Failed`
    without it.
    """
    deployment = deploy(pre)
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    recorder = deploy_recorder(pre, 0)
    init = registration(owner, deployment.verifier, NEW_KEY)
    p = intent(deployment, recorder, init)
    digest = p.digest(CHAIN_ID, owner)
    calldata = migrate_calldata(p, init, owner_signature(owner, digest))

    if fork.is_eip_enabled(8151):
        logs = [migrated_log(deployment, owner, digest)]
        outcome = recorded(0, 1, 0, 0)
        owner_post = Account(
            code=KERNEL,
            nonce=1,
            storage=kernel_storage(deployment.verifier, NEW_KEY),
        )
    else:
        logs = []
        outcome = recorded(0, 0, 4, selector_word(error("P4Failed")))
        owner_post = Account(
            code=delegation_indicator(deployment.migrator),
            nonce=1,
            storage={},
        )
    tx = Transaction(
        sender=relayer,
        to=recorder,
        data=record(0, owner, calldata),
        gas_limit=GAS_LIMIT,
        authorization_list=[
            AuthorizationTuple(
                address=deployment.migrator, nonce=0, signer=owner
            )
        ],
        expected_receipt=TransactionReceipt(status=1, logs=logs),
    )
    blockchain_test(
        pre=pre,
        blocks=[deployment.block, Block(txs=[tx])],
        post={
            **deployment.post(),
            owner: owner_post,
            recorder: Account(storage=outcome),
        },
    )


def opcode_bytes(code: Bytecode) -> set[int]:
    """Return the bytes at opcode positions of `code` (PUSH data skipped)."""
    raw = bytes(code)
    found = set()
    position = 0
    while position < len(raw):
        opcode = raw[position]
        found.add(opcode)
        if 0x60 <= opcode <= 0x7F:
            position += opcode - 0x5F
        position += 1
    return found


SETCODEFROM, DELEGATECALL, CALLCODE, SELFDESTRUCT = 0xA7, 0xF4, 0xF2, 0xFF
STORAGE_OPCODES = {0x54, 0x55, 0x5C, 0x5D}  # SLOAD SSTORE TLOAD TSTORE


def test_contract_opcodes(
    state_test: StateTestFiller,
    pre: Alloc,
) -> None:
    """
    Test the opcode bytes of the verifier and the kernel, then that the
    verifier deploys as is.

    The verifier has no `0xA7`, `0xF4` or `0xF2` at an opcode position, and
    no storage access or `SELFDESTRUCT` (stateless, immutable). The kernel
    has no `SETCODEFROM`, `DELEGATECALL`, `CALLCODE` or `SELFDESTRUCT` (R6).
    """
    verifier = verifier_code()
    assert opcode_bytes(verifier).isdisjoint(
        {SETCODEFROM, DELEGATECALL, CALLCODE}
    )
    assert opcode_bytes(verifier).isdisjoint(STORAGE_OPCODES | {SELFDESTRUCT})
    assert opcode_bytes(KERNEL).isdisjoint(
        {SETCODEFROM, DELEGATECALL, CALLCODE, SELFDESTRUCT}
    )
    # The walk does see opcodes that are there.
    assert SETCODEFROM in opcode_bytes(Op.SETCODEFROM(0))

    deployed = pre.deploy_contract(verifier)
    state_test(
        pre=pre,
        tx=Transaction(sender=pre.fund_eoa(), to=deployed),
        post={deployed: Account(code=verifier, storage={})},
    )


def verify_calldata(key: bytes, digest: Hash, signature: bytes) -> bytes:
    """Return the calldata of `verify(key, hash, signature)`."""
    return VERIFY + encode(
        ["bytes", "bytes32", "bytes"], [key, bytes(digest), signature]
    )


@pytest.mark.parametrize(
    "case,valid",
    [
        pytest.param("valid", True, id="valid"),
        pytest.param("wrong_hash", False, id="wrong_hash"),
        pytest.param("other_key", False, id="other_key"),
        pytest.param("empty_key", False, id="empty_key"),
        pytest.param("short_signature", False, id="short_signature"),
        pytest.param("trailing_bytes", False, id="trailing_bytes"),
        pytest.param("key_length_lies", False, id="key_length_lies"),
        pytest.param(
            "signature_length_lies", False, id="signature_length_lies"
        ),
    ],
)
def test_p256_verifier(
    state_test: StateTestFiller,
    pre: Alloc,
    case: str,
    valid: bool,
) -> None:
    """
    Test the verifier returns `0x024ad318` only for a valid P256 signature
    under a canonical encoding of a 64-byte key and a 64-byte signature,
    and `0xffffffff` otherwise.
    """
    verifier = pre.deploy_contract(verifier_code())
    recorder = deploy_recorder(pre, 0)
    digest = keccak(b"setcodefrom poc m1 verifier digest")
    key = NEW_KEY.public_key
    signature = NEW_KEY.sign(digest)
    if case == "valid":
        calldata = verify_calldata(key, digest, signature)
    elif case == "wrong_hash":
        calldata = verify_calldata(key, keccak(b"other"), signature)
    elif case == "other_key":
        calldata = verify_calldata(OTHER_KEY.public_key, digest, signature)
    elif case == "empty_key":
        calldata = verify_calldata(b"", digest, signature)
    elif case == "short_signature":
        calldata = verify_calldata(key, digest, signature[:63])
    elif case == "trailing_bytes":
        calldata = verify_calldata(key, digest, signature) + bytes(32)
    elif case in ("key_length_lies", "signature_length_lies"):
        # Canonical layout and size, but one length word says 32 bytes.
        edited = bytearray(verify_calldata(key, digest, signature))
        head = 4 + (0x60 if case == "key_length_lies" else 0xC0)
        edited[head : head + 32] = (32).to_bytes(32, "big")
        calldata = bytes(edited)
    else:
        raise ValueError(f"unknown case: {case}")

    tx = Transaction(
        sender=pre.fund_eoa(),
        to=recorder,
        data=record(0, verifier, calldata),
        gas_limit=GAS_LIMIT,
    )
    magic = VERIFIER_MAGIC if valid else INVALID
    state_test(
        pre=pre,
        tx=tx,
        post={
            recorder: Account(storage=recorded(0, 1, 32, selector_word(magic)))
        },
    )
