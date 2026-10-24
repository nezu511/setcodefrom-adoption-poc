"""
Bytecode of the PoC contracts, written with the `Op` DSL.

- the P256 verifier (ERC-7913),
- the reference kernel (single key, minimal; not conforming, see below),
- `MigrationCheck` and `Migrator` (Route A),
- `Recorder`, a test harness that records the outcome of one call.

The kernel implements R1, R3, R4, R7 and R8 only. This tree has no
EIP-8141, so it has no `VERIFY` (R2) and no relay path: an account that
adopts it cannot act afterwards. It shows the guard and Route A, not a
usable account.

Jumps use `Label`s resolved by `assemble`, with a fixed `PUSH2` per jump.
"""

from dataclasses import dataclass, field
from itertools import count
from typing import Any, Iterable, Union

from execution_testing import Address, Bytecode, Hash, Op

from .helpers import (
    ACCOUNT_MESSAGE_TYPEHASH,
    DOMAIN_TYPEHASH,
    MIGRATION_TUPLE,
    MIGRATION_TYPEHASH,
    NAME_HASH,
    REGISTRATION_TYPEHASH,
    SCOPE_EXECUTION,
    VERSION_HASH,
    keccak,
    selector,
)

ECRECOVER = Address(0x01)
P256VERIFY = Address(0x100)
# EIP-8141's ENTRY_POINT, the caller of every DEFAULT frame.
ENTRY_POINT = Address(0xAA)

# Function selectors.
VERIFY = selector("verify(bytes,bytes32,bytes)")
INITIALIZE = selector("initialize(bytes)")
IS_VALID_SIGNATURE = selector("isValidSignature(bytes32,bytes)")
ON_ERC721_RECEIVED = selector(
    "onERC721Received(address,address,uint256,bytes)"
)
ON_ERC1155_RECEIVED = selector(
    "onERC1155Received(address,address,uint256,uint256,bytes)"
)
ON_ERC1155_BATCH_RECEIVED = selector(
    "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"
)
MIGRATE = selector(f"migrate({MIGRATION_TUPLE},bytes,bytes)")
BEGIN = selector(f"begin({MIGRATION_TUPLE},bytes)")
FINISH = selector(f"finish({MIGRATION_TUPLE},bytes)")
REVOKE = selector("revoke(bytes32)")

# Return values.
VERIFIER_MAGIC = bytes.fromhex("024ad318")  # ERC-7913 verify.selector
ERC1271_MAGIC = bytes.fromhex("1626ba7e")
INVALID = bytes.fromhex("ffffffff")

MIGRATED_TOPIC = keccak(b"Migrated(address,bytes32,bytes32,uint8)")
ROUTE_A = 1
ROUTE_B = 2

# Storage of the kernel.
INITIALIZED_CODE_HASH_SLOT = (
    int.from_bytes(keccak(b"adoption-profile.initialized-codehash")) - 1
)
KERNEL_NAMESPACE = (
    int.from_bytes(
        keccak(
            (
                int.from_bytes(keccak(b"adoption-profile.kernel.v1")) - 1
            ).to_bytes(32, "big")
        )
    )
    & ~0xFF
)
AUTHORITY_VERIFIER = KERNEL_NAMESPACE
AUTHORITY_SCOPE = KERNEL_NAMESPACE + 1
AUTHORITY_KEY_LENGTH = KERNEL_NAMESPACE + 2
AUTHORITY_KEY = KERNEL_NAMESPACE + 3  # one slot per 32-byte word


def error(name: str) -> bytes:
    """Return the selector of the custom error `name()`."""
    return selector(f"{name}()")


# Custom errors, so a harness can tell which check reverted.
ERRORS = [
    # MigrationCheck
    "BadSignatureLength",
    "UnsupportedRoute",
    "WrongCheck",
    "Expired",
    "Revoked",
    "P1Failed",
    "NotBegun",
    "P2Failed",
    "P4Failed",
    # Migrator
    "AtMigratorAddress",
    "NotExecutor",
    "ExecutorIsEntryPoint",
    "InitDataMismatch",
    "SourceHashMismatch",
    "SetCodeFailed",
    "InitializeFailed",
    # Kernel
    "NotSelf",
    "AlreadyInitialized",
    "BadInitData",
    "NotExecutionCapable",
    "InvalidRegistration",
]


_label_ids = count()


@dataclass(eq=False)
class Label:
    """A jump destination; `assemble` places a `JUMPDEST` there."""

    name: str = field(default_factory=lambda: f"L{next(_label_ids)}")


@dataclass(frozen=True)
class Jump:
    """Jump to `label`, if `condition` is non-zero when one is given."""

    label: Label
    condition: Bytecode | None = None


@dataclass(frozen=True)
class PushLabel:
    """Push the offset of `label`, used as a return address."""

    label: Label


Part = Union[Bytecode, Label, Jump, PushLabel]


def _flatten(parts: Iterable[Any]) -> list[Part]:
    flat: list[Part] = []
    for part in parts:
        if isinstance(part, (Bytecode, Label, Jump, PushLabel)):
            flat.append(part)
        else:
            flat.extend(_flatten(part))
    return flat


def _size(part: Part) -> int:
    if isinstance(part, Label):
        return 1
    if isinstance(part, Jump):
        condition = len(part.condition) if part.condition is not None else 0
        return condition + 4
    if isinstance(part, PushLabel):
        return 3
    return len(part)


def assemble(*parts: Any) -> Bytecode:
    """Resolve the labels in `parts` (nested lists allowed); return code."""
    flat = _flatten(parts)
    offsets: dict[int, int] = {}
    position = 0
    for part in flat:
        if isinstance(part, Label):
            offsets[id(part)] = position
        position += _size(part)
    code = Bytecode()
    for part in flat:
        if isinstance(part, Label):
            code += Op.JUMPDEST
        elif isinstance(part, Jump):
            target = Op.PUSH2(offsets[id(part.label)])
            if part.condition is None:
                code += target + Op.JUMP
            else:
                code += part.condition + target + Op.JUMPI
        elif isinstance(part, PushLabel):
            code += Op.PUSH2(offsets[id(part.label)])
        else:
            code += part
    assert len(code) == position
    return code


def revert_with(name: str) -> Bytecode:
    """Revert with the custom error `name()`."""
    assert name in ERRORS, name
    return Op.MSTORE(0, int.from_bytes(error(name))) + Op.REVERT(28, 4)


def require(condition: Bytecode, name: str) -> list[Any]:
    """Revert with `name()` unless `condition` is non-zero."""
    ok = Label()
    return [Jump(ok, condition), revert_with(name), ok]


def return_word(value: bytes) -> Bytecode:
    """Return `value` left-aligned in one word, as ABI encodes `bytes4`."""
    return Op.MSTORE(0, int.from_bytes(value) << 224) + Op.RETURN(0, 32)


def function_selector() -> Bytecode:
    """Push the first four bytes of the calldata."""
    return Op.SHR(224, Op.CALLDATALOAD(0))


def dispatch(cases: list[tuple[bytes, Label]]) -> list[Any]:
    """Jump to the label of the matching selector, or revert."""
    jumps: list[Any] = [
        Jump(label, Op.EQ(function_selector(), int.from_bytes(sel)))
        for sel, label in cases
    ]
    return jumps + [Op.REVERT(0, 0)]


def ceil32(value: Bytecode) -> Bytecode:
    """Round `value` up to a multiple of 32."""
    return Op.AND(Op.ADD(value, 31), Op.NOT(31))


def typed_digest(struct_hash: Bytecode, account: Bytecode) -> Bytecode:
    """
    Push the EIP-712 digest of `struct_hash` under the PoC domain, with
    `verifyingContract = account`. Uses memory [0, 0xa0) as scratch, after
    `struct_hash` and `account` are evaluated.
    """
    return (
        struct_hash
        + account
        + Op.MSTORE(0x00, DOMAIN_TYPEHASH)
        + Op.MSTORE(0x20, NAME_HASH)
        + Op.MSTORE(0x40, VERSION_HASH)
        + Op.MSTORE(0x60, Op.CHAINID)
        # verifyingContract, from the stack
        + Op.PUSH1(0x80)
        + Op.MSTORE
        + Op.SHA3(0x00, 0xA0)
        # 0x1901 ‖ domainSeparator ‖ structHash
        + Op.MSTORE(0x00, 0x1901 << 240)
        + Op.PUSH1(0x02)
        + Op.MSTORE
        + Op.PUSH1(0x22)
        + Op.MSTORE
        + Op.SHA3(0x00, 0x42)
    )


def receive_hooks() -> tuple[list[tuple[bytes, Label]], list[Any]]:
    """
    Return the dispatch cases and bodies of the ERC-721/1155 receive hooks,
    which return their own selector and make no calls.
    """
    cases = []
    bodies: list[Any] = []
    for sel in (
        ON_ERC721_RECEIVED,
        ON_ERC1155_RECEIVED,
        ON_ERC1155_BATCH_RECEIVED,
    ):
        label = Label()
        cases.append((sel, label))
        bodies += [label, return_word(sel)]
    return cases, bodies


def receive_ether() -> tuple[Jump, list[Any]]:
    """Return the jump and body that accept empty calldata (ETH)."""
    label = Label()
    return Jump(label, Op.ISZERO(Op.CALLDATASIZE)), [label, Op.STOP]


# ---------------------------------------------------------------------------
# P256 verifier (ERC-7913)
# ---------------------------------------------------------------------------

# Canonical calldata of verify(bytes key, bytes32 hash, bytes signature)
# with a 64-byte key (x ‖ y) and a 64-byte signature (r ‖ s).
VERIFY_KEY_OFFSET = 0x60
VERIFY_SIGNATURE_OFFSET = 0xC0
VERIFY_CALLDATA_SIZE = 4 + 0x60 + (32 + 64) * 2


def verifier_code() -> Bytecode:
    """
    Return the stateless P256 verifier.

    It accepts only the canonical encoding of a 64-byte key and a 64-byte
    signature, calls P256VERIFY with `hash ‖ r ‖ s ‖ x ‖ y`, and returns
    `0x024ad318` when the precompile returns 1, else `0xffffffff`.
    """
    verify, invalid = Label(), Label()
    key = 4 + VERIFY_KEY_OFFSET
    signature = 4 + VERIFY_SIGNATURE_OFFSET
    return assemble(
        dispatch([(VERIFY, verify)]),
        verify,
        # Canonical encoding: no trailing bytes, standard offsets.
        Jump(invalid, Op.ISZERO(Op.EQ(Op.CALLDATASIZE, VERIFY_CALLDATA_SIZE))),
        Jump(invalid, Op.ISZERO(Op.EQ(Op.CALLDATALOAD(4), VERIFY_KEY_OFFSET))),
        Jump(
            invalid,
            Op.ISZERO(Op.EQ(Op.CALLDATALOAD(68), VERIFY_SIGNATURE_OFFSET)),
        ),
        # Lengths: a 64-byte key (never empty) and a 64-byte signature.
        Jump(invalid, Op.ISZERO(Op.EQ(Op.CALLDATALOAD(key), 64))),
        Jump(invalid, Op.ISZERO(Op.EQ(Op.CALLDATALOAD(signature), 64))),
        # hash ‖ r ‖ s ‖ x ‖ y
        Op.MSTORE(0, Op.CALLDATALOAD(36))
        + Op.CALLDATACOPY(32, signature + 32, 64)
        + Op.CALLDATACOPY(96, key + 32, 64)
        + Op.MSTORE(160, 0),
        Jump(
            invalid,
            Op.ISZERO(
                Op.STATICCALL(
                    gas=Op.GAS,
                    address=P256VERIFY,
                    args_offset=0,
                    args_size=160,
                    ret_offset=160,
                    ret_size=32,
                )
            ),
        ),
        Jump(invalid, Op.ISZERO(Op.EQ(Op.RETURNDATASIZE, 32))),
        Jump(invalid, Op.ISZERO(Op.EQ(Op.MLOAD(160), 1))),
        return_word(VERIFIER_MAGIC),
        invalid,
        return_word(INVALID),
    )


# ---------------------------------------------------------------------------
# Reference kernel
# ---------------------------------------------------------------------------

# Memory: [0, 0x100) scratch, then locals, then key and signature bytes.
K_VERIFIER = 0x100
K_DIGEST = 0x120
K_KEY_LENGTH = 0x140
K_SIGNATURE = 0x160  # where the signature bytes start
K_SIGNATURE_LENGTH = 0x180
K_VALID = 0x1A0
K_BUFFER = 0x1C0
K_INDEX = 0x1E0
K_INIT_DATA = 0x200
K_KEY = 0x300  # the key bytes start here


def _verify_authority(entry: Label) -> list[Any]:
    """
    Return the one shared verification of (authority, digest, signature).

    Input: the verifier, digest, key and signature in the `K_*` locals and
    the return address on the stack. Output: `K_VALID`. It STATICCALLs
    `verify(key, digest, signature)` and accepts only the ERC-7913 magic.
    """
    buffer = Op.MLOAD(K_BUFFER)
    key_length = Op.MLOAD(K_KEY_LENGTH)
    signature_length = Op.MLOAD(K_SIGNATURE_LENGTH)
    # Offsets inside the calldata, after the selector.
    signature_offset = Op.ADD(0x80, ceil32(key_length))
    signature_head = Op.ADD(Op.ADD(buffer, 4), signature_offset)
    calldata_size = Op.ADD(
        Op.ADD(signature_offset, 36), ceil32(signature_length)
    )
    return [
        entry,
        # Build the calldata in fresh memory, whose padding is zero.
        Op.MSTORE(K_BUFFER, Op.MSIZE)
        + Op.MSTORE(buffer, int.from_bytes(VERIFY) << 224)
        + Op.MSTORE(Op.ADD(buffer, 4), 0x60)
        + Op.MSTORE(Op.ADD(buffer, 36), Op.MLOAD(K_DIGEST))
        + Op.MSTORE(Op.ADD(buffer, 68), signature_offset)
        + Op.MSTORE(Op.ADD(buffer, 100), key_length)
        + Op.MCOPY(Op.ADD(buffer, 132), K_KEY, key_length)
        + Op.MSTORE(signature_head, signature_length)
        + Op.MCOPY(
            Op.ADD(signature_head, 32),
            Op.MLOAD(K_SIGNATURE),
            signature_length,
        )
        + Op.MSTORE(0, 0)
        # In sequence: the checks of the output run after the call (the
        # DSL would evaluate a sibling argument before it).
        + Op.STATICCALL(
            gas=Op.GAS,
            address=Op.MLOAD(K_VERIFIER),
            args_offset=buffer,
            args_size=calldata_size,
            ret_offset=0,
            ret_size=32,
        )
        + Op.EQ(Op.RETURNDATASIZE, 32)
        + Op.AND
        + Op.EQ(Op.MLOAD(0), int.from_bytes(VERIFIER_MAGIC) << 224)
        + Op.AND
        + Op.PUSH2(K_VALID)
        + Op.MSTORE
        + Op.JUMP,
    ]


def _call_verify_authority(entry: Label) -> list[Any]:
    back = Label()
    return [PushLabel(back), Jump(entry), back]


def _copy_key(store: bool) -> list[Any]:
    """Copy the key words between `K_KEY` memory and storage."""
    loop, done = Label(), Label()
    index = Op.MLOAD(K_INDEX)
    memory = Op.ADD(K_KEY, Op.MUL(index, 32))
    slot = Op.ADD(AUTHORITY_KEY, index)
    if store:
        body = Op.SSTORE(slot, Op.MLOAD(memory))
    else:
        body = Op.MSTORE(memory, Op.SLOAD(slot))
    return [
        Op.MSTORE(K_INDEX, 0),
        loop,
        Jump(
            done,
            Op.ISZERO(Op.LT(Op.MUL(index, 32), Op.MLOAD(K_KEY_LENGTH))),
        ),
        body + Op.MSTORE(K_INDEX, Op.ADD(index, 1)),
        Jump(loop),
        done,
    ]


def kernel_code() -> Bytecode:
    """
    Return the reference kernel.

    `initialize(bytes initData)` with initData = abi.encode(address verifier,
    bytes key, uint8 scope, bytes proof) installs one authority (R4);
    `isValidSignature(bytes32, bytes)` verifies over `AccountMessage` (R8);
    empty calldata and the ERC-721/1155 hooks accept transfers (R7). Both
    signature paths call one shared verification (R3). It never uses
    ecrecover (R1), and has no SETCODEFROM, DELEGATECALL, CALLCODE or
    SELFDESTRUCT (R6).
    """
    initialize, is_valid, invalid = Label(), Label(), Label()
    verify_authority = Label()
    hook_cases, hook_bodies = receive_hooks()
    receive_jump, receive_body = receive_ether()

    base = Op.MLOAD(K_INIT_DATA)  # calldata offset of initData's content
    scope = Op.CALLDATALOAD(Op.ADD(base, 64))
    key_head = Op.ADD(base, Op.CALLDATALOAD(Op.ADD(base, 32)))
    proof_head = Op.ADD(base, Op.CALLDATALOAD(Op.ADD(base, 96)))
    key_length = Op.MLOAD(K_KEY_LENGTH)
    signature_head = Op.ADD(4, Op.CALLDATALOAD(36))

    return assemble(
        receive_jump,
        dispatch(
            [(INITIALIZE, initialize), (IS_VALID_SIGNATURE, is_valid)]
            + hook_cases
        ),
        receive_body,
        hook_bodies,
        # --- initialize(bytes initData) --------------------------------
        initialize,
        require(Op.EQ(Op.CALLER, Op.ADDRESS), "NotSelf"),
        require(
            Op.ISZERO(
                Op.EQ(
                    Op.SLOAD(INITIALIZED_CODE_HASH_SLOT),
                    Op.EXTCODEHASH(Op.ADDRESS),
                )
            ),
            "AlreadyInitialized",
        ),
        Op.MSTORE(K_INIT_DATA, Op.ADD(Op.CALLDATALOAD(4), 36))
        + Op.MSTORE(K_VERIFIER, Op.CALLDATALOAD(base)),
        require(
            Op.AND(
                Op.ISZERO(Op.SHR(160, Op.MLOAD(K_VERIFIER))),
                Op.ISZERO(Op.SHR(8, scope)),
            ),
            "BadInitData",
        ),
        require(Op.AND(scope, SCOPE_EXECUTION), "NotExecutionCapable"),
        Op.MSTORE(K_KEY_LENGTH, Op.CALLDATALOAD(key_head))
        + Op.CALLDATACOPY(K_KEY, Op.ADD(key_head, 32), key_length)
        + Op.MSTORE(K_SIGNATURE, Op.ADD(K_KEY, ceil32(key_length)))
        + Op.MSTORE(K_SIGNATURE_LENGTH, Op.CALLDATALOAD(proof_head))
        + Op.CALLDATACOPY(
            Op.MLOAD(K_SIGNATURE),
            Op.ADD(proof_head, 32),
            Op.MLOAD(K_SIGNATURE_LENGTH),
        ),
        # Registration(verifier, keccak256(key), scope)
        _registration_digest(scope),
        _call_verify_authority(verify_authority),
        require(Op.MLOAD(K_VALID), "InvalidRegistration"),
        # Install exactly this authority, whatever storage held before.
        Op.SSTORE(AUTHORITY_VERIFIER, Op.MLOAD(K_VERIFIER))
        + Op.SSTORE(AUTHORITY_SCOPE, scope)
        + Op.SSTORE(AUTHORITY_KEY_LENGTH, key_length),
        _copy_key(store=True),
        Op.SSTORE(INITIALIZED_CODE_HASH_SLOT, Op.EXTCODEHASH(Op.ADDRESS))
        + Op.STOP,
        # --- isValidSignature(bytes32 hash, bytes signature) -------------
        is_valid,
        Op.MSTORE(0x00, ACCOUNT_MESSAGE_TYPEHASH)
        + Op.MSTORE(0x20, Op.CALLDATALOAD(4))
        + Op.MSTORE(K_DIGEST, typed_digest(Op.SHA3(0x00, 0x40), Op.ADDRESS)),
        # Only an execution-capable authority signs for the account.
        Jump(
            invalid,
            Op.ISZERO(Op.AND(Op.SLOAD(AUTHORITY_SCOPE), SCOPE_EXECUTION)),
        ),
        Op.MSTORE(K_VERIFIER, Op.SLOAD(AUTHORITY_VERIFIER))
        + Op.MSTORE(K_KEY_LENGTH, Op.SLOAD(AUTHORITY_KEY_LENGTH)),
        _copy_key(store=False),
        Op.MSTORE(K_SIGNATURE, Op.ADD(K_KEY, ceil32(key_length)))
        + Op.MSTORE(K_SIGNATURE_LENGTH, Op.CALLDATALOAD(signature_head))
        + Op.CALLDATACOPY(
            Op.MLOAD(K_SIGNATURE),
            Op.ADD(signature_head, 32),
            Op.MLOAD(K_SIGNATURE_LENGTH),
        ),
        _call_verify_authority(verify_authority),
        Jump(invalid, Op.ISZERO(Op.MLOAD(K_VALID))),
        return_word(ERC1271_MAGIC),
        invalid,
        return_word(INVALID),
        # --- shared verification (R3) ----------------------------------
        _verify_authority(verify_authority),
    )


def _registration_digest(scope: Bytecode) -> Bytecode:
    """Store the `Registration` digest of the authority in `K_DIGEST`."""
    return (
        Op.MSTORE(0x00, REGISTRATION_TYPEHASH)
        + Op.MSTORE(0x20, Op.MLOAD(K_VERIFIER))
        + Op.MSTORE(0x40, Op.SHA3(K_KEY, Op.MLOAD(K_KEY_LENGTH)))
        + Op.MSTORE(0x60, scope)
        + Op.MSTORE(K_DIGEST, typed_digest(Op.SHA3(0x00, 0x80), Op.ADDRESS))
    )


# ---------------------------------------------------------------------------
# MigrationCheck
# ---------------------------------------------------------------------------

# Calldata of begin/finish(Migration p, bytes ownerSig): p is static, so its
# six words are inline after the selector.
P_SOURCE = 4
P_CODE_HASH = 4 + 32
P_INIT_DATA_HASH = 4 + 64
P_DEADLINE = 4 + 96
P_EXECUTOR = 4 + 128
P_CHECK = 4 + 160
P_SIZE = 192
OWNER_SIG_OFFSET = 4 + P_SIZE  # word holding the offset of ownerSig

C_DIGEST = 0x100
C_MARK_KEY = 0x120  # keccak256(account ‖ D)
C_SIGNATURE_HASH = 0x140
C_V = 0x160
C_R = 0x180
C_S = 0x1A0


def delegation_indicator(target: Address) -> bytes:
    """Return the EIP-7702 delegation indicator to `target`."""
    return b"\xef\x01\x00" + bytes(target)


def _decode_intent() -> list[Any]:
    """
    Check that ownerSig is 65 bytes `r ‖ s ‖ v`, load it, and compute `D`
    and the (account, D) key, with the account as `msg.sender`.
    """
    signature_head = Op.ADD(4, Op.CALLDATALOAD(OWNER_SIG_OFFSET))
    return [
        require(
            Op.EQ(Op.CALLDATALOAD(signature_head), 65), "BadSignatureLength"
        ),
        Op.MSTORE(C_R, Op.CALLDATALOAD(Op.ADD(signature_head, 32)))
        + Op.MSTORE(C_S, Op.CALLDATALOAD(Op.ADD(signature_head, 64)))
        + Op.MSTORE(
            C_V, Op.SHR(248, Op.CALLDATALOAD(Op.ADD(signature_head, 96)))
        )
        + Op.CALLDATACOPY(0, Op.ADD(signature_head, 32), 65)
        + Op.MSTORE(C_SIGNATURE_HASH, Op.SHA3(0, 65))
        # Migration(source, codeHash, initDataHash, deadline, executor, check)
        + Op.MSTORE(0, MIGRATION_TYPEHASH)
        + Op.CALLDATACOPY(32, P_SOURCE, P_SIZE)
        + Op.MSTORE(
            C_DIGEST,
            typed_digest(Op.SHA3(0, 32 + P_SIZE), Op.CALLER),
        )
        + Op.MSTORE(0, Op.CALLER)
        + Op.MSTORE(32, Op.MLOAD(C_DIGEST))
        + Op.MSTORE(C_MARK_KEY, Op.SHA3(0, 64)),
    ]


def _ecrecover_owner_signature(ecrecover: Address) -> Bytecode:
    """
    Call ecrecover(D, v, r, s) with all the remaining gas and push the
    success flag. P1 and P4 make this same call.
    """
    return (
        Op.MSTORE(0, Op.MLOAD(C_DIGEST))
        + Op.MSTORE(32, Op.MLOAD(C_V))
        + Op.MSTORE(64, Op.MLOAD(C_R))
        + Op.MSTORE(96, Op.MLOAD(C_S))
        + Op.STATICCALL(
            gas=Op.GAS,
            address=ecrecover,
            args_offset=0,
            args_size=128,
            ret_offset=128,
            ret_size=32,
        )
    )


def migration_check_code(
    migrator: Address, ecrecover: Address = ECRECOVER
) -> Bytecode:
    """
    Return `MigrationCheck` bound to `migrator` (Route A only).

    `ecrecover` is the precompile `0x01`; only tests pass another address
    (a fake ecrecover, never part of the reference implementation).

    - begin: route A (caller holds the delegation indicator to `migrator`),
      `p.check == this`, deadline, not revoked, P1; then marks (account, D)
      in transient storage with the hash of ownerSig.
    - finish: the mark (cleared), P2, P4 (`success == 1` and
      `returndatasize == 0`; 32 zero bytes are refused), then `Migrated`.
    - revoke(D): records (msg.sender, D).
    """
    begin, finish, revoke = Label(), Label(), Label()
    indicator_hash = keccak(delegation_indicator(migrator))
    return assemble(
        dispatch([(BEGIN, begin), (FINISH, finish), (REVOKE, revoke)]),
        # --- begin(p, ownerSig) ------------------------------------------
        begin,
        _decode_intent(),
        require(
            Op.EQ(Op.EXTCODEHASH(Op.CALLER), indicator_hash),
            "UnsupportedRoute",
        ),
        require(Op.EQ(Op.CALLDATALOAD(P_CHECK), Op.ADDRESS), "WrongCheck"),
        require(
            Op.ISZERO(Op.GT(Op.TIMESTAMP, Op.CALLDATALOAD(P_DEADLINE))),
            "Expired",
        ),
        require(Op.ISZERO(Op.SLOAD(Op.MLOAD(C_MARK_KEY))), "Revoked"),
        # P1: succeeds and returns the account.
        require(_ecrecover_owner_signature(ecrecover), "P1Failed"),
        require(Op.EQ(Op.RETURNDATASIZE, 32), "P1Failed"),
        require(Op.EQ(Op.MLOAD(128), Op.CALLER), "P1Failed"),
        Op.TSTORE(Op.MLOAD(C_MARK_KEY), Op.MLOAD(C_SIGNATURE_HASH)) + Op.STOP,
        # --- finish(p, ownerSig) -----------------------------------------
        finish,
        _decode_intent(),
        require(
            Op.EQ(Op.TLOAD(Op.MLOAD(C_MARK_KEY)), Op.MLOAD(C_SIGNATURE_HASH)),
            "NotBegun",
        ),
        Op.TSTORE(Op.MLOAD(C_MARK_KEY), 0),
        # P2: exactly the signed code was adopted.
        require(
            Op.EQ(Op.EXTCODEHASH(Op.CALLER), Op.CALLDATALOAD(P_CODE_HASH)),
            "P2Failed",
        ),
        # P4: the same call succeeds with empty output. Decided by
        # returndatasize alone: on empty output the output word still holds
        # what this frame wrote there before (the account, from the digest).
        require(_ecrecover_owner_signature(ecrecover), "P4Failed"),
        require(Op.ISZERO(Op.RETURNDATASIZE), "P4Failed"),
        Op.MSTORE(0, Op.MLOAD(C_DIGEST))
        + Op.MSTORE(32, ROUTE_A)
        + Op.LOG3(
            0,
            64,
            MIGRATED_TOPIC,
            Op.CALLER,
            Op.CALLDATALOAD(P_CODE_HASH),
        )
        + Op.STOP,
        # --- revoke(bytes32 D) ---------------------------------------------
        revoke,
        Op.MSTORE(0, Op.CALLER)
        + Op.MSTORE(32, Op.CALLDATALOAD(4))
        + Op.SSTORE(Op.SHA3(0, 64), 1)
        + Op.STOP,
    )


# ---------------------------------------------------------------------------
# Migrator
# ---------------------------------------------------------------------------

# Calldata of migrate(Migration p, bytes initData, bytes ownerSig).
INIT_DATA_OFFSET = 4 + P_SIZE
MIGRATE_OWNER_SIG_OFFSET = 4 + P_SIZE + 32

M_INIT_DATA_HEAD = 0x100
M_CHECK_CALL_SIZE = 0x120
M_INITIALIZE_CALL = 0x140
M_CHECK_CALL = 0x200  # begin/finish calldata, then initData for hashing


def migrator_code(self_address: Address, check: Address) -> Bytecode:
    """
    Return `Migrator`, deployed at `self_address` and bound to `check`.

    migrate(p, initData, ownerSig), following the Route A pseudo-code:
    never at its own address; `msg.sender == p.executor`;
    `p.executor != ENTRY_POINT` (added ahead of draft v2.7);
    `keccak256(initData) == p.initDataHash`; CHECK.begin;
    `EXTCODEHASH(p.source) == p.codeHash`; `SETCODEFROM(p.source) == 1`;
    `address(this).call(initialize(initData))` succeeds; CHECK.finish.
    Reverts from CHECK are bubbled up. No storage; besides migrate, only
    receive hooks that make no calls.
    """
    migrate = Label()
    revert_from_check = Label()
    hook_cases, hook_bodies = receive_hooks()
    receive_jump, receive_body = receive_ether()

    init_data_head = Op.MLOAD(M_INIT_DATA_HEAD)
    init_data_length = Op.CALLDATALOAD(init_data_head)
    signature_head = Op.ADD(4, Op.CALLDATALOAD(MIGRATE_OWNER_SIG_OFFSET))
    initialize_call = Op.MLOAD(M_INITIALIZE_CALL)

    def call_check(function: bytes) -> list[Any]:
        return [
            # The selector lands at M_CHECK_CALL, right before p.
            Op.MSTORE(M_CHECK_CALL - 28, int.from_bytes(function)),
            Jump(
                revert_from_check,
                Op.ISZERO(
                    Op.CALL(
                        gas=Op.GAS,
                        address=check,
                        args_offset=M_CHECK_CALL,
                        args_size=Op.MLOAD(M_CHECK_CALL_SIZE),
                    )
                ),
            ),
        ]

    return assemble(
        receive_jump,
        dispatch([(MIGRATE, migrate)] + hook_cases),
        receive_body,
        hook_bodies,
        migrate,
        require(
            Op.ISZERO(Op.EQ(Op.ADDRESS, self_address)), "AtMigratorAddress"
        ),
        require(Op.EQ(Op.CALLER, Op.CALLDATALOAD(P_EXECUTOR)), "NotExecutor"),
        require(
            Op.ISZERO(Op.EQ(Op.CALLDATALOAD(P_EXECUTOR), ENTRY_POINT)),
            "ExecutorIsEntryPoint",
        ),
        Op.MSTORE(
            M_INIT_DATA_HEAD, Op.ADD(4, Op.CALLDATALOAD(INIT_DATA_OFFSET))
        )
        + Op.CALLDATACOPY(
            M_CHECK_CALL, Op.ADD(init_data_head, 32), init_data_length
        ),
        require(
            Op.EQ(
                Op.SHA3(M_CHECK_CALL, init_data_length),
                Op.CALLDATALOAD(P_INIT_DATA_HASH),
            ),
            "InitDataMismatch",
        ),
        # begin/finish calldata: selector ‖ p ‖ 0xe0 ‖ ownerSig
        Op.CALLDATACOPY(M_CHECK_CALL + 4, P_SOURCE, P_SIZE)
        + Op.MSTORE(M_CHECK_CALL + 4 + P_SIZE, P_SIZE + 32)
        + Op.CALLDATACOPY(
            M_CHECK_CALL + 4 + P_SIZE + 32,
            signature_head,
            Op.ADD(32, ceil32(Op.CALLDATALOAD(signature_head))),
        )
        + Op.MSTORE(
            M_CHECK_CALL_SIZE,
            Op.ADD(4 + P_SIZE + 64, ceil32(Op.CALLDATALOAD(signature_head))),
        ),
        call_check(BEGIN),
        # Fail early; P2 in finish is what guards the hash.
        require(
            Op.EQ(
                Op.EXTCODEHASH(Op.CALLDATALOAD(P_SOURCE)),
                Op.CALLDATALOAD(P_CODE_HASH),
            ),
            "SourceHashMismatch",
        ),
        require(
            Op.EQ(Op.SETCODEFROM(Op.CALLDATALOAD(P_SOURCE)), 1),
            "SetCodeFailed",
        ),
        # initialize(initData) on the adopted code, built in fresh memory.
        Op.MSTORE(M_INITIALIZE_CALL, Op.MSIZE)
        + Op.MSTORE(initialize_call, int.from_bytes(INITIALIZE) << 224)
        + Op.MSTORE(Op.ADD(initialize_call, 4), 0x20)
        + Op.CALLDATACOPY(
            Op.ADD(initialize_call, 36),
            init_data_head,
            Op.ADD(32, ceil32(init_data_length)),
        ),
        require(
            Op.CALL(
                gas=Op.GAS,
                address=Op.ADDRESS,
                args_offset=initialize_call,
                args_size=Op.ADD(68, ceil32(init_data_length)),
            ),
            "InitializeFailed",
        ),
        call_check(FINISH),
        Op.STOP,
        revert_from_check,
        Op.RETURNDATACOPY(0, 0, Op.RETURNDATASIZE)
        + Op.REVERT(0, Op.RETURNDATASIZE),
    )


# ---------------------------------------------------------------------------
# Recorder (test harness)
# ---------------------------------------------------------------------------

SUCCESS, RETURNDATASIZE, RETURN_WORD = range(3)


def recorder_code() -> Bytecode:
    """
    Return a harness that calls `target` with `payload` and all its gas,
    forwarding the call value, and stores the success flag, the return data
    size and the first return word (zero-padded) at `base`, `base + 1` and
    `base + 2`. Calldata: `base ‖ target ‖ payload`.
    """
    payload_size = Op.SUB(Op.CALLDATASIZE, 64)
    base = Op.CALLDATALOAD(0)
    return (
        Op.CALLDATACOPY(0, 64, payload_size)
        + Op.SSTORE(
            Op.ADD(base, SUCCESS),
            Op.CALL(
                gas=Op.GAS,
                address=Op.CALLDATALOAD(32),
                value=Op.CALLVALUE,
                args_offset=0,
                args_size=payload_size,
            ),
        )
        + Op.SSTORE(Op.ADD(base, RETURNDATASIZE), Op.RETURNDATASIZE)
        + Op.MSTORE(0, 0)
        + Op.RETURNDATACOPY(0, 0, Op.RETURNDATASIZE)
        + Op.SSTORE(Op.ADD(base, RETURN_WORD), Op.MLOAD(0))
        + Op.STOP
    )


def code_hash(code: Bytecode | bytes) -> Hash:
    """Return the keccak256 of `code`."""
    return keccak(bytes(code))
