"""
Test ecrecover of one signature before and after its signer adopts code via
[EIP-8298: SETCODEFROM](https://eips.ethereum.org/EIPS/eip-8298).

Under [EIP-8151: Account Code Restricted ecRecover](https://eips.ethereum.org/EIPS/eip-8151)
the precompile withholds the address of a signer that holds code other than
a delegation designation, so the same input that recovered the owner before
the adoption returns empty output after it. Without EIP-8151 the address is
still returned. The expectations branch on `fork.is_eip_enabled(8151)`, so
the same file fills on a tree with and a tree without EIP-8151.
"""

from typing import Dict

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Bytes,
    Fork,
    Hash,
    Op,
    StateTestFiller,
    Storage,
    Transaction,
)

from ..eip8298_setcodefrom.helpers import (
    ADOPT_FROM_CALLDATA,
    RESULT_SLOT,
    SENTINEL,
    word,
)
from ..eip8298_setcodefrom.spec import ref_spec_8298
from .helpers import ecrecover_gas, sign_digest

REFERENCE_SPEC_GIT_PATH = ref_spec_8298.git_path
REFERENCE_SPEC_VERSION = ref_spec_8298.version

pytestmark = pytest.mark.valid_from("EIP8298")

ECRECOVER = Address(0x01)
DIGEST = Hash(Bytes(b"setcodefrom poc m0 digest").keccak256())
SOURCE_CODE = Op.STOP
EMPTY_CODE_HASH = Bytes(b"").keccak256()

# Memory layout of the probe: the 128-byte input, then the output word.
INPUT_SIZE = 128
OUTPUT_OFFSET = INPUT_SIZE

# Slots of one probe run, relative to the base in its first calldata word.
# The probe calls ecrecover twice: the first call finds the signer cold, the
# second finds it warmed by the first (with EIP-8151 only).
SUCCESS, RETURNDATASIZE, OUTPUT, GAS_USED = range(4)
COLD_CALL = 0
WARM_CALL = 4
OWNER_CODE_HASH = 8
SLOTS_PER_RUN = 9

BEFORE_BASE = 0x100
AFTER_BASE = 0x200


def ecrecover_call() -> Bytecode:
    """Call ecrecover with all the remaining gas."""
    return Op.CALL(
        gas=Op.GAS,
        address=ECRECOVER,
        args_offset=0,
        args_size=INPUT_SIZE,
        ret_offset=OUTPUT_OFFSET,
        ret_size=32,
        # Precompiles are always warm.
        address_warm=True,
    )


def store_at(offset: int) -> Bytecode:
    """Store the top of the stack at the run's base plus `offset`."""
    return Op.ADD(Op.CALLDATALOAD(0), offset) + Op.SSTORE


def measured_ecrecover(call: int) -> Bytecode:
    """
    Call ecrecover and store its success, return data size, output word and
    the gas between two `GAS` readings around the call.
    """
    return (
        # An empty output leaves this zero, which is what the probe stores.
        Op.MSTORE(OUTPUT_OFFSET, 0)
        + Op.GAS
        + ecrecover_call()
        + Op.GAS
        + Op.SWAP1
        + store_at(call + SUCCESS)
        + Op.SWAP1
        + Op.SUB
        + store_at(call + GAS_USED)
        + Op.RETURNDATASIZE
        + store_at(call + RETURNDATASIZE)
        + Op.MLOAD(OUTPUT_OFFSET)
        + store_at(call + OUTPUT)
    )


def deploy_probe(
    pre: Alloc, owner: Address, digest: Hash, v: int, r: int, s: int
) -> Address:
    """
    Deploy a contract that runs ecrecover on a fixed input and records the
    owner's code hash, with every slot it writes pre-set to `SENTINEL`.
    """
    code = (
        Op.MSTORE(0, digest)
        + Op.MSTORE(32, v)
        + Op.MSTORE(64, r)
        + Op.MSTORE(96, s)
        + measured_ecrecover(COLD_CALL)
        + measured_ecrecover(WARM_CALL)
        # Read after both calls so it does not warm the owner for them.
        + Op.EXTCODEHASH(owner)
        + store_at(OWNER_CODE_HASH)
        + Op.STOP
    )
    storage = Storage()
    for base in (BEFORE_BASE, AFTER_BASE):
        for offset in range(SLOTS_PER_RUN):
            storage[base + offset] = SENTINEL
    return pre.deploy_contract(code, storage=storage)


def expected_run(
    fork: Fork,
    base: int,
    *,
    recovered: bool,
    output: Address | None,
    owner_code_hash: Hash,
) -> Dict[int, int]:
    """
    Return the slots of one probe run; `output` is the address returned, or
    None for empty output.
    """
    # The two GAS readings bracket the call's own cost, the precompile charge
    # and the second GAS.
    overhead = (ecrecover_call() + Op.GAS).gas_cost(fork)
    storage: Dict[int, int] = {}
    for call, address_warm in ((COLD_CALL, False), (WARM_CALL, True)):
        # Empty output is a successful call that returns no data, not an
        # address of zero.
        storage[base + call + SUCCESS] = 1
        storage[base + call + RETURNDATASIZE] = 0 if output is None else 32
        storage[base + call + OUTPUT] = (
            0 if output is None else int.from_bytes(output)
        )
        storage[base + call + GAS_USED] = overhead + ecrecover_gas(
            fork, recovered=recovered, address_warm=address_warm
        )
    storage[base + OWNER_CODE_HASH] = int.from_bytes(owner_code_hash)
    return storage


def test_ecrecover_before_and_after_adoption(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test that the owner's signature recovers the owner before it adopts
    code, and that the same input is withheld after it only with EIP-8151.
    """
    owner = pre.fund_eoa()
    relayer = pre.fund_eoa()
    sender = pre.fund_eoa()
    source = pre.deploy_contract(SOURCE_CODE)
    shell = pre.deploy_contract(
        ADOPT_FROM_CALLDATA, storage={RESULT_SLOT: SENTINEL}
    )
    v, r, s = sign_digest(owner, DIGEST)
    probe = deploy_probe(pre, owner, DIGEST, v, r, s)

    probe_before = Transaction(sender=sender, to=probe, data=Hash(BEFORE_BASE))
    # Relayed, so the owner's authorization takes nonce 0.
    adoption = Transaction(
        sender=relayer,
        to=owner,
        data=word(source),
        authorization_list=[
            AuthorizationTuple(address=shell, nonce=0, signer=owner)
        ],
    )
    probe_after = Transaction(sender=sender, to=probe, data=Hash(AFTER_BASE))

    withheld = fork.is_eip_enabled(8151)
    storage = {
        **expected_run(
            fork,
            BEFORE_BASE,
            recovered=True,
            output=owner,
            owner_code_hash=EMPTY_CODE_HASH,
        ),
        **expected_run(
            fork,
            AFTER_BASE,
            recovered=True,
            output=None if withheld else owner,
            owner_code_hash=SOURCE_CODE.keccak256(),
        ),
    }

    blockchain_test(
        pre=pre,
        blocks=[
            Block(txs=[probe_before]),
            Block(txs=[adoption]),
            Block(txs=[probe_after]),
        ],
        post={
            probe: Account(storage=storage),
            # SETCODEFROM returned 1 in the owner's frame and left the
            # source's code on the owner.
            owner: Account(
                code=SOURCE_CODE, nonce=1, storage={RESULT_SLOT: 1}
            ),
        },
    )


@pytest.mark.parametrize(
    "broken",
    [
        pytest.param("invalid-v", id="invalid-v"),
        pytest.param("zero-s", id="zero-s"),
    ],
)
def test_ecrecover_broken_signature(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
    broken: str,
) -> None:
    """
    Test that a broken signature of an owner without code also returns
    empty output, with or without EIP-8151.
    """
    owner = pre.fund_eoa()
    v, r, s = sign_digest(owner, DIGEST)
    if broken == "invalid-v":
        v += 2
    elif broken == "zero-s":
        s = 0
    else:
        raise ValueError(f"unknown broken: {broken}")
    probe = deploy_probe(pre, owner, DIGEST, v, r, s)

    storage = {
        base + offset: SENTINEL
        for base in (AFTER_BASE,)
        for offset in range(SLOTS_PER_RUN)
    }
    storage.update(
        expected_run(
            fork,
            BEFORE_BASE,
            recovered=False,
            output=None,
            owner_code_hash=EMPTY_CODE_HASH,
        )
    )

    tx = Transaction(sender=pre.fund_eoa(), to=probe, data=Hash(BEFORE_BASE))

    state_test(pre=pre, post={probe: Account(storage=storage)}, tx=tx)
