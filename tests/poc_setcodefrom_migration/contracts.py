"""
Bytecode of the PoC contracts, written with the `Op` DSL.

- the P256 verifier (ERC-7913),
- the reference kernel (single key, minimal; not conforming, see below),
- `MigrationCheck` and `Migrator` (Route A),
- `Recorder`, a test harness that records the outcome of one call.

`Migrator` and `MigrationCheck` are deployed from initcode whose
constructor writes immutables into the runtime code (see `Immutables`).

The kernel implements R1, R3, R4, R7 and R8 only. This tree has no
EIP-8141, so it has no `VERIFY` (R2) and no relay path: an account that
adopts it cannot act afterwards. It shows the guard and Route A, not a
usable account.

Jumps use `Label`s resolved by `assemble`, with a fixed `PUSH2` per jump.
"""

from dataclasses import dataclass, field
from functools import cache
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
    SCOPE_PAYMENT,
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
    "CheckCodeMismatch",
    "InitDataMismatch",
    "SourceHashMismatch",
    "SetCodeFailed",
    "InitializeFailed",
    "NotInitialized",
    "StaleRecord",
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


def push_operands(code: bytes) -> dict[int, int]:
    """Return {offset of the push data: its length} of each PUSH in `code`."""
    operands = {}
    position = 0
    while position < len(code):
        opcode = code[position]
        if 0x60 <= opcode <= 0x7F:
            operands[position + 1] = opcode - 0x5F
            position += opcode - 0x5F
        position += 1
    return operands


class Immutables:
    """
    Values that a constructor learns when it runs and writes into the
    runtime code it returns, as Solidity's immutables.

    Each use is a `PUSH32`. `push(name)` returns one with a sentinel
    operand unique to that use; `template` then finds every sentinel in
    the assembled code and returns the code with those operands zeroed
    and their offsets, by name. The constructor copies the template to
    memory and `MSTORE`s each value over its 32-byte operand.
    """

    def __init__(self, contract: str) -> None:
        self.contract = contract
        self.sentinels: dict[str, list[bytes]] = {}

    def push(self, name: str) -> Bytecode:
        """Return a `PUSH32` for one use of the immutable `name`."""
        uses = self.sentinels.setdefault(name, [])
        sentinel = keccak(
            f"immutable:{self.contract}:{name}:{len(uses)}".encode()
        )
        uses.append(bytes(sentinel))
        return Op.PUSH32(int.from_bytes(sentinel))

    def template(self, code: Bytecode, uses: dict[str, int]) -> "Template":
        """
        Return `code` with the sentinels zeroed, after checking that `uses`
        gives the number of uses of each name, and that each sentinel
        occurs once, as the operand of a `PUSH32`.
        """
        raw = bytearray(bytes(code))
        operands = push_operands(bytes(raw))
        assert {n: len(s) for n, s in self.sentinels.items()} == uses
        offsets: dict[str, list[int]] = {}
        for name, sentinels in self.sentinels.items():
            for sentinel in sentinels:
                at = raw.find(sentinel)
                assert at > 0 and raw.find(sentinel, at + 1) == -1
                assert raw[at - 1] == 0x7F and operands.get(at) == 32
                raw[at : at + 32] = bytes(32)
                offsets.setdefault(name, []).append(at)
        return Template(bytes(raw), offsets)


@dataclass(frozen=True)
class Template:
    """Runtime code whose immutable operands are zero, and their offsets."""

    code: bytes
    offsets: dict[str, list[int]]

    def fill(self, values: dict[str, bytes]) -> bytes:
        """Return the code with each operand set to its 32-byte value."""
        assert values.keys() == self.offsets.keys()
        code = bytearray(self.code)
        for name, offsets in self.offsets.items():
            assert len(values[name]) == 32
            for at in offsets:
                code[at : at + 32] = values[name]
        return bytes(code)


def as_word(value: Address | Hash) -> bytes:
    """Return `value` as one 32-byte word, as `MSTORE` writes it."""
    return bytes(value).rjust(32, b"\x00")


def constructor_initcode(
    template: Template,
    values: dict[str, Bytecode],
    *,
    memory: int,
    prologue: Any = lambda _: [],
    trailer: bytes = b"",
) -> bytes:
    """
    Return `constructor ‖ template.code ‖ trailer`. The constructor runs
    `prologue(offset of trailer)`, copies the template to `memory`, writes
    each value (code that pushes it) over its operands with `MSTORE`, and
    returns the runtime code.

    Offsets and lengths inside the initcode are pushed with a fixed
    `PUSH2`, and the constructor is built twice: once to learn its size,
    then with the offsets that follow from it.
    """
    size = len(template.code)

    def constructor(start: int) -> Bytecode:
        return assemble(
            prologue(Op.PUSH2(start + size)),
            Op.CODECOPY(memory, Op.PUSH2(start), Op.PUSH2(size)),
            [
                Op.MSTORE(memory + at, values[name])
                for name, offsets in template.offsets.items()
                for at in offsets
            ],
            Op.RETURN(memory, Op.PUSH2(size)),
        )

    start = len(constructor(0))
    code = constructor(start)
    assert len(code) == start
    return bytes(code) + template.code + trailer


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
                # Only EIP-8141's approval bits (payment, execution).
                Op.ISZERO(
                    Op.AND(scope, Op.NOT(SCOPE_PAYMENT | SCOPE_EXECUTION))
                ),
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


@cache
def _migration_check_template(ecrecover: Address) -> Template:
    """
    Return the runtime code of `MigrationCheck` (Route A only), with its
    one immutable, `MIGRATOR_INDICATOR_HASH`, still zero.

    `ecrecover` is the precompile `0x01`; only tests pass another address
    (a fake ecrecover, never part of the reference implementation).

    - begin: route A (caller holds the delegation indicator to its
      `Migrator`: `EXTCODEHASH(caller) == MIGRATOR_INDICATOR_HASH`),
      `p.check == this`, deadline, not revoked, P1; then marks
      (account, D) in transient storage with the hash of ownerSig.
    - finish: the mark (cleared), P2, P4 (`success == 1` and
      `returndatasize == 0`; 32 zero bytes are refused), then `Migrated`.
    - revoke(D): records (msg.sender, D).
    """
    begin, finish, revoke = Label(), Label(), Label()
    immutables = Immutables("MigrationCheck")
    indicator_hash = immutables.push("MIGRATOR_INDICATOR_HASH")
    code = assemble(
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
    return immutables.template(code, {"MIGRATOR_INDICATOR_HASH": 1})


def migration_check_code(
    migrator: Address, ecrecover: Address = ECRECOVER
) -> bytes:
    """
    Return the runtime code of `MigrationCheck` as `migrator` creates it:
    `MIGRATOR_INDICATOR_HASH` is the hash of the delegation indicator to
    `migrator`.

    Tests also place this code directly, with any address as `migrator`.
    """
    return _migration_check_template(ecrecover).fill(
        {
            "MIGRATOR_INDICATOR_HASH": as_word(
                keccak(delegation_indicator(migrator))
            )
        }
    )


def migration_check_initcode(ecrecover: Address = ECRECOVER) -> bytes:
    """
    Return the initcode of `MigrationCheck`. Its constructor learns its
    `Migrator` from `msg.sender` (`CALLER`): it hashes the 23-byte
    delegation indicator `0xef0100 ‖ CALLER` and writes the hash into
    the runtime code as `MIGRATOR_INDICATOR_HASH`.
    """
    return constructor_initcode(
        _migration_check_template(ecrecover),
        {"MIGRATOR_INDICATOR_HASH": Op.MLOAD(0x20)},
        memory=0x40,
        # Bytes 9..31 of word 0 hold the indicator; its hash goes to 0x20.
        prologue=lambda _: Op.MSTORE(
            0, Op.OR(Op.SHL(160, 0xEF0100), Op.CALLER)
        )
        + Op.MSTORE(0x20, Op.SHA3(9, 23)),
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


@cache
def _migrator_template() -> Template:
    """
    Return the runtime code of `Migrator`, with its immutables still zero:
    `SELF` (its own address), `CHECK` (the `MigrationCheck` it created)
    and `CHECK_HASH` (that contract's code hash right after creation).

    migrate(p, initData, ownerSig), following the Route A pseudo-code:
    never at its own address; `msg.sender == p.executor`;
    `p.executor != ENTRY_POINT` (v2.7's Route A details, "Executor");
    `EXTCODEHASH(CHECK) == CHECK_HASH` (below);
    `keccak256(initData) == p.initDataHash`; CHECK.begin;
    `EXTCODEHASH(p.source) == p.codeHash`; the stale-record check (below);
    `SETCODEFROM(p.source) == 1`;
    `address(this).call(initialize(initData))` succeeds; the check of R4's
    record (below); CHECK.finish.
    Reverts from CHECK are bubbled up. No storage; besides migrate, only
    receive hooks that make no calls.

    Ahead of draft v2.7 (a v2.8 candidate): right after `initialize`
    returns, `SLOAD(INITIALIZED_CODE_HASH_SLOT) == EXTCODEHASH(this)` is
    required (`NotInitialized`). v2.7's P3 only requires that the call did
    not revert, which code with a permissive fallback satisfies without
    running any initialization. The check reads R4's record, so it shows
    that code with the R4 record ran; it does not judge the code (code
    that writes the slot and installs nothing passes).

    Also ahead of draft v2.7 (a v2.8 candidate): right before `SETCODEFROM`,
    `SLOAD(INITIALIZED_CODE_HASH_SLOT) != p.codeHash` is required
    (`StaleRecord`). Without it, a record of the new code's hash left by an
    earlier delegate would satisfy the check after `initialize` with nothing
    run. The slot need not be empty: an earlier initialization can leave a
    different hash there. Like the check after `initialize`, it reads only
    the record's value; it does not judge the code.

    Also beyond draft v2.7 (a v2.8 candidate): the constructor creates the
    `MigrationCheck` and records its code hash (`migrator_initcode`), and
    every `migrate` requires `EXTCODEHASH(CHECK) == CHECK_HASH`
    (`CheckCodeMismatch`) before calling `begin`. A call to an address
    without code succeeds, so without the check, a `MigrationCheck` that
    is missing would let `begin` and `finish` succeed with nothing run.
    That happens when `Migrator`'s runtime code is placed without running
    its constructor, as a genesis preinstall can do. The check also
    requires the recorded hash to be neither 0 nor `keccak256("")`, the
    two values `EXTCODEHASH` gives for an account without code, so that
    `CHECK` has code: runtime code whose immutables were never filled (a
    compiler's `deployedBytecode` leaves them zero) or were filled with
    such a hash is refused too. The check reads `CHECK`, the address
    recorded in this code, not `p.check`.
    """
    migrate = Label()
    immutables = Immutables("Migrator")
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
                        address=immutables.push("CHECK"),
                        args_offset=M_CHECK_CALL,
                        args_size=Op.MLOAD(M_CHECK_CALL_SIZE),
                    )
                ),
            ),
        ]

    code = assemble(
        receive_jump,
        dispatch([(MIGRATE, migrate)] + hook_cases),
        receive_body,
        hook_bodies,
        migrate,
        require(
            Op.ISZERO(Op.EQ(Op.ADDRESS, immutables.push("SELF"))),
            "AtMigratorAddress",
        ),
        require(Op.EQ(Op.CALLER, Op.CALLDATALOAD(P_EXECUTOR)), "NotExecutor"),
        require(
            Op.ISZERO(Op.EQ(Op.CALLDATALOAD(P_EXECUTOR), ENTRY_POINT)),
            "ExecutorIsEntryPoint",
        ),
        # The MigrationCheck still holds the code it had when created:
        # EXTCODEHASH(CHECK) == CHECK_HASH, and CHECK_HASH is neither 0 nor
        # keccak256(""), so CHECK has code. CHECK_HASH is pushed once.
        require(
            immutables.push("CHECK_HASH")  # [h]
            + Op.DUP1  # [h, h]
            + Op.EXTCODEHASH(immutables.push("CHECK"))
            + Op.EQ  # [h, h == EXTCODEHASH(CHECK)]
            + Op.SWAP1
            + Op.DUP1
            + Op.PUSH32(int.from_bytes(EMPTY_CODE_HASH))
            + Op.EQ  # [match, h, h == keccak256("")]
            + Op.SWAP1
            + Op.ISZERO
            + Op.OR  # [match, h == keccak256("") || h == 0]
            + Op.ISZERO
            + Op.AND,
            "CheckCodeMismatch",
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
        # Stale record: R4's slot must not already name the code to adopt.
        require(
            Op.ISZERO(
                Op.EQ(
                    Op.SLOAD(INITIALIZED_CODE_HASH_SLOT),
                    Op.CALLDATALOAD(P_CODE_HASH),
                )
            ),
            "StaleRecord",
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
            Op.ADD(32, init_data_length),
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
        # P3, read from the account's own storage (Migrator runs as the
        # account): R4's record must be the hash of the code now installed.
        require(
            Op.EQ(
                Op.SLOAD(INITIALIZED_CODE_HASH_SLOT),
                Op.EXTCODEHASH(Op.ADDRESS),
            ),
            "NotInitialized",
        ),
        call_check(FINISH),
        Op.STOP,
        revert_from_check,
        Op.RETURNDATACOPY(0, 0, Op.RETURNDATASIZE)
        + Op.REVERT(0, Op.RETURNDATASIZE),
    )
    return immutables.template(code, {"CHECK": 3, "SELF": 1, "CHECK_HASH": 1})


def migrator_code(
    self_address: Address, check: Address, check_hash: Hash
) -> bytes:
    """
    Return the runtime code of `Migrator` as its constructor writes it at
    `self_address`: `SELF = self_address`, `CHECK = check` (the address of
    the `MigrationCheck` it created) and `CHECK_HASH = check_hash`.
    """
    return _migrator_template().fill(
        {
            "SELF": as_word(self_address),
            "CHECK": as_word(check),
            "CHECK_HASH": as_word(check_hash),
        }
    )


EMPTY_CODE_HASH = keccak(b"")
# Memory of Migrator's constructor.
X_CHECK = 0x00
X_CHECK_HASH = 0x20
X_CREATE_INPUT = 0x40


def migrator_initcode(ecrecover: Address = ECRECOVER) -> bytes:
    """
    Return the initcode of `Migrator`: constructor ‖ runtime template ‖
    `MigrationCheck`'s initcode (built with `ecrecover`).

    The constructor creates the `MigrationCheck` with `CREATE` (at
    `compute_create_address(Migrator, 1)`, a contract's first nonce), and
    reverts with `CheckCodeMismatch` unless `CREATE` returned an address
    whose code hash is neither 0 nor `keccak256("")`. It then writes
    `ADDRESS`, that address and that hash into the runtime code as `SELF`,
    `CHECK` and `CHECK_HASH`. Nothing in the initcode depends on the
    deployer or on `Migrator`'s address.
    """
    check_initcode = migration_check_initcode(ecrecover)
    check_size = len(check_initcode)
    check = Op.MLOAD(X_CHECK)
    check_hash = Op.MLOAD(X_CHECK_HASH)

    def prologue(trailer: Bytecode) -> list[Any]:
        return [
            Op.CODECOPY(X_CREATE_INPUT, trailer, Op.PUSH2(check_size))
            + Op.MSTORE(
                X_CHECK, Op.CREATE(0, X_CREATE_INPUT, Op.PUSH2(check_size))
            )
            + Op.MSTORE(X_CHECK_HASH, Op.EXTCODEHASH(check)),
            require(
                Op.AND(
                    Op.AND(
                        Op.ISZERO(Op.ISZERO(check)),
                        Op.ISZERO(Op.ISZERO(check_hash)),
                    ),
                    Op.ISZERO(
                        Op.EQ(check_hash, int.from_bytes(EMPTY_CODE_HASH))
                    ),
                ),
                "CheckCodeMismatch",
            ),
        ]

    return constructor_initcode(
        _migrator_template(),
        {"SELF": Op.ADDRESS, "CHECK": check, "CHECK_HASH": check_hash},
        # The runtime code is copied after CREATE's input.
        memory=X_CREATE_INPUT + (check_size + 31) // 32 * 32,
        prologue=prologue,
        trailer=check_initcode,
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
