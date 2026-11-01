"""
Test-only contracts of M2 and M3. NONE OF THIS IS REFERENCE IMPLEMENTATION.

They are bad examples of adopted code, sources that change, a fake
ecrecover, a stipend sender, a step harness, code whose `initialize`
calls `finish`, code that only writes R4's record, code that stores a
word of its `initialize` calldata and a verifier that writes storage,
used only to reproduce the failure modes and to reach the guard's
checks. The reference contracts
(verifier, kernel, MigrationCheck, Migrator) and the `Recorder` harness of
M1 stay in `contracts.py`.

Since Migrator reads R4's record after `initialize` (see `migrator_code`),
the bad examples that must get through Route A write that record
(`record_initialization`), as the kernel does; the permissive fallback
example does not.
"""

from typing import Any

from execution_testing import Address, Bytecode, Op

from .contracts import (
    ECRECOVER,
    ERC1271_MAGIC,
    INITIALIZE,
    INITIALIZED_CODE_HASH_SLOT,
    INVALID,
    IS_VALID_SIGNATURE,
    P_CHECK,
    VERIFIER_MAGIC,
    Jump,
    Label,
    assemble,
    ceil32,
    dispatch,
    function_selector,
    receive_ether,
    receive_hooks,
    return_word,
)
from .helpers import selector

# Custom error of the step harness, outside the reference `ERRORS`.
HARNESS_SET_CODE_FAILED = selector("HarnessSetCodeFailed()")


def record_initialization() -> Bytecode:
    """
    TEST ONLY: write R4's record, as the kernel's `initialize` does: the
    hash of the code now installed, at `INITIALIZED_CODE_HASH_SLOT`.
    """
    return Op.SSTORE(INITIALIZED_CODE_HASH_SLOT, Op.EXTCODEHASH(Op.ADDRESS))


def bad_example_permissive_fallback_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: a bad example of FM3 whose
    fallback succeeds for every selector it does not know.

    It accepts ETH with empty calldata, answers the three receive hooks,
    answers `isValidSignature` with the invalid value, and returns
    successfully with no data for anything else, `initialize(bytes)`
    included. So `address(this).call(initialize(initData))` succeeds while
    no initialization runs and nothing is recorded. (The same shape as a
    Safe whose fallback handler is unset: its `FallbackManager` returns
    with no data for unknown selectors, safe-smart-account 247b8ce; this
    PoC does not run Safe.)
    """
    is_valid = Label()
    receive_jump, receive_body = receive_ether()
    hook_cases, hook_bodies = receive_hooks()
    known = [(IS_VALID_SIGNATURE, is_valid)] + hook_cases
    return assemble(
        receive_jump,
        [
            Jump(label, Op.EQ(function_selector(), int.from_bytes(sel)))
            for sel, label in known
        ],
        Op.STOP,  # the permissive fallback
        receive_body,
        hook_bodies,
        is_valid,
        return_word(INVALID),
    )


def bad_example_self_recovery_wallet_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: a bad example of FM1.

    `isValidSignature(hash, sig)` with a 65-byte `r ‖ s ‖ v` returns the
    ERC-1271 magic only when `ecrecover(hash, sig)` succeeds with 32 bytes
    of output equal to `ADDRESS`. The output is read correctly; what is bad
    is relying on recovery to the account's own address. `initialize(bytes)`
    writes R4's record and does nothing else, so the code can pass Route A
    (the record shows only that `initialize` ran, not what the code is).
    """
    initialize, is_valid, invalid = Label(), Label(), Label()
    receive_jump, receive_body = receive_ether()
    signature = Op.ADD(4, Op.CALLDATALOAD(36))  # head of the bytes `sig`
    return assemble(
        receive_jump,
        dispatch([(INITIALIZE, initialize), (IS_VALID_SIGNATURE, is_valid)]),
        receive_body,
        initialize,
        record_initialization(),
        Op.STOP,
        is_valid,
        Jump(invalid, Op.ISZERO(Op.EQ(Op.CALLDATALOAD(signature), 65))),
        # hash ‖ v ‖ r ‖ s
        Op.MSTORE(0, Op.CALLDATALOAD(4))
        + Op.MSTORE(32, Op.SHR(248, Op.CALLDATALOAD(Op.ADD(signature, 96))))
        + Op.MSTORE(64, Op.CALLDATALOAD(Op.ADD(signature, 32)))
        + Op.MSTORE(96, Op.CALLDATALOAD(Op.ADD(signature, 64)))
        + Op.MSTORE(128, 0),
        # One statement per step: the call, then each check of its output.
        Jump(
            invalid,
            Op.ISZERO(
                Op.STATICCALL(
                    gas=Op.GAS,
                    address=ECRECOVER,
                    args_offset=0,
                    args_size=128,
                    ret_offset=128,
                    ret_size=32,
                )
            ),
        ),
        Jump(invalid, Op.ISZERO(Op.EQ(Op.RETURNDATASIZE, 32))),
        Jump(invalid, Op.ISZERO(Op.EQ(Op.MLOAD(128), Op.ADDRESS))),
        return_word(ERC1271_MAGIC),
        invalid,
        return_word(INVALID),
    )


def bad_example_revert_everything_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: a bad example of FM4, code
    with no receive path that reverts whatever it is called with.
    """
    return Op.REVERT(0, 0)


def bad_example_record_only_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: code that, on any call, writes
    R4's record and stops. It installs nothing, so an account that adopts
    it is left to whoever adopts it next; the tests use it as the code an
    attacker would choose.
    """
    return record_initialization() + Op.STOP


# Slot where `tool_init_data_reader_code` stores the word it reads.
INIT_DATA_READER_SLOT = 0
# Calldata offset of the second word of `initData` in `initialize(bytes)`.
INIT_DATA_SECOND_WORD = 4 + 32 + 32 + 32


def tool_init_data_reader_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: code to adopt that, on any
    call (so its `initialize`), writes R4's record and stores the second
    word of `initData` in its `initialize(bytes)` calldata,
    `CALLDATALOAD(100)`, at `INIT_DATA_READER_SLOT`. With `initData`
    shorter than 64 bytes, that word holds the padding `Migrator` passed.
    """
    return (
        record_initialization()
        + Op.SSTORE(
            INIT_DATA_READER_SLOT, Op.CALLDATALOAD(INIT_DATA_SECOND_WORD)
        )
        + Op.STOP
    )


def tool_stateful_verifier_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: a verifier that writes its own
    storage (slot 0) and then returns the ERC-7913 magic for any input. A
    kernel that calls it with `STATICCALL` sees the call fail.
    """
    return Op.SSTORE(0, 1) + return_word(VERIFIER_MAGIC)


def tool_stipend_sender_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: send 1 wei to the address in
    calldata word 0 with a `CALL` that forwards 0 gas, so the callee runs
    on the 2,300-gas stipend alone, and store the success flag at the slot
    in calldata word 1.
    """
    return (
        Op.SSTORE(
            Op.CALLDATALOAD(32),
            Op.CALL(gas=0, address=Op.CALLDATALOAD(0), value=1),
        )
        + Op.STOP
    )


def tool_self_replacing_source_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: a source of FM5 that, when
    called, replaces its own code with the code of the address in calldata
    word 0.
    """
    return Op.POP(Op.SETCODEFROM(Op.CALLDATALOAD(0))) + Op.STOP


def tool_readopting_source_code(replacement: Address) -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: a source of FM5 whose code,
    once adopted, replaces the adopting account's code with
    `replacement`'s on any call (so its `initialize` does), then writes
    R4's record for the code now installed, and succeeds. The record is
    forged (it names the replacement), so Migrator's check of the record
    passes and it is `finish` that stops the migration, at P2.
    """
    return (
        Op.POP(Op.SETCODEFROM(replacement))
        + record_initialization()
        + Op.STOP
    )


# What the fake ecrecover does while the owner is delegated (P1) ...
FAKE_RETURN_OWNER = "return_owner"
FAKE_REVERT_WITH_OWNER = "revert_with_owner"
# ... and otherwise (P4).
FAKE_ZERO_WORD = "zero_word"
FAKE_EMPTY = "empty"
FAKE_REVERT = "revert"


def tool_fake_ecrecover_code(
    owner: Address, *, while_delegated: str, otherwise: str
) -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION (and not a precompile): stands
    in for ecrecover at another address.

    While `owner`'s code is 23 bytes long (a delegation indicator) it
    returns `owner` as one word, like P1 expects (`FAKE_RETURN_OWNER`), or
    reverts with `owner` as the 32-byte revert data
    (`FAKE_REVERT_WITH_OWNER`). Otherwise it returns 32 zero bytes
    (`FAKE_ZERO_WORD`, the output of older EIP-8151 drafts), empty output
    (`FAKE_EMPTY`) or reverts with no data (`FAKE_REVERT`). It writes no
    state, so a `STATICCALL` can run it.
    """
    delegated = Label()
    after = {
        FAKE_ZERO_WORD: Op.RETURN(0, 32),
        FAKE_EMPTY: Op.RETURN(0, 0),
        FAKE_REVERT: Op.REVERT(0, 0),
    }[otherwise]
    during = {
        FAKE_RETURN_OWNER: Op.RETURN(0, 32),
        FAKE_REVERT_WITH_OWNER: Op.REVERT(0, 32),
    }[while_delegated]
    return assemble(
        Op.MSTORE(0, 0),
        Jump(delegated, Op.EQ(Op.EXTCODESIZE(owner), 23)),
        after,
        delegated,
        Op.MSTORE(0, owner) + during,
    )


# Calldata offset of the first word of `initData` in `initialize(bytes)`.
INIT_DATA_FIRST_WORD = 4 + 32 + 32


def tool_finish_calling_source_code(*, calls_finish: bool) -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: code to adopt whose
    `initialize(bytes initData)` calls `MigrationCheck.finish` itself.

    `initData` is one word: the address of a holder whose code is the
    calldata of `finish(p, ownerSig)`. (`p` and `ownerSig` cannot sit in
    `initData` itself, since `p.initDataHash` is the hash of `initData`.)
    With `calls_finish`, `initialize` copies that calldata, calls `p.check`
    with it and all the gas, ignores the result, and succeeds. Without it
    (the control), `initialize` only succeeds. Either way `initialize`
    first writes R4's record, so Migrator's check of the record passes.
    Any other call reverts.
    """
    initialize = Label()
    holder = Op.CALLDATALOAD(INIT_DATA_FIRST_WORD)
    body = (
        record_initialization()
        + Op.EXTCODECOPY(holder, 0, 0, Op.EXTCODESIZE(holder))
        + Op.POP(
            Op.CALL(
                gas=Op.GAS,
                address=Op.MLOAD(P_CHECK),
                args_offset=0,
                args_size=Op.EXTCODESIZE(holder),
            )
        )
        + Op.STOP
    )
    return assemble(
        dispatch([(INITIALIZE, initialize)]),
        initialize,
        body if calls_finish else record_initialization() + Op.STOP,
    )


# Steps of the step harness.
STEP_CALL = 0
STEP_SET_CODE = 1

H_STEP = 0x00  # calldata offset of the current step
H_NEXT = 0x20  # calldata offset of the next step
H_BUFFER = 0x100


def tool_step_harness_code() -> Bytecode:
    """
    TEST ONLY, NOT REFERENCE IMPLEMENTATION: an EIP-7702 delegate that runs
    the steps in its calldata, in order, as the delegating account.

    Each step is `kind ‖ target ‖ length ‖ payload` (three words, then the
    payload padded to 32 bytes). `STEP_CALL` calls `target` with `payload`
    and all the gas, and bubbles a revert up as is. `STEP_SET_CODE` runs
    `SETCODEFROM(target)` and reverts with `HarnessSetCodeFailed()` unless
    it returns 1. It lets a test call `begin`, `SETCODEFROM`, `initialize`
    and `finish` in any order and with any arguments.
    """
    loop, set_code, bubble, done = Label(), Label(), Label(), Label()
    step = Op.MLOAD(H_STEP)
    kind = Op.CALLDATALOAD(step)
    target = Op.CALLDATALOAD(Op.ADD(step, 32))
    length = Op.CALLDATALOAD(Op.ADD(step, 64))
    parts: list[Any] = [
        Op.MSTORE(H_NEXT, 0),
        loop,
        Jump(done, Op.ISZERO(Op.LT(Op.MLOAD(H_NEXT), Op.CALLDATASIZE))),
        Op.MSTORE(H_STEP, Op.MLOAD(H_NEXT))
        + Op.MSTORE(H_NEXT, Op.ADD(Op.ADD(step, 96), ceil32(length))),
        Jump(set_code, kind),
        Op.CALLDATACOPY(H_BUFFER, Op.ADD(step, 96), length),
        Jump(
            bubble,
            Op.ISZERO(
                Op.CALL(
                    gas=Op.GAS,
                    address=target,
                    args_offset=H_BUFFER,
                    args_size=length,
                )
            ),
        ),
        Jump(loop),
        set_code,
        Jump(loop, Op.EQ(Op.SETCODEFROM(target), 1)),
        Op.MSTORE(0, int.from_bytes(HARNESS_SET_CODE_FAILED))
        + Op.REVERT(28, 4),
        bubble,
        Op.RETURNDATACOPY(0, 0, Op.RETURNDATASIZE)
        + Op.REVERT(0, Op.RETURNDATASIZE),
        done,
        Op.STOP,
    ]
    return assemble(parts)


def step(kind: int, target: Address, payload: bytes = b"") -> bytes:
    """Encode one step of the step harness."""
    padded = payload + bytes(-len(payload) % 32)
    return (
        kind.to_bytes(32, "big")
        + bytes(12)
        + bytes(target)
        + len(payload).to_bytes(32, "big")
        + padded
    )
