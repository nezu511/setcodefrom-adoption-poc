"""
Scenario helpers shared by the M2 tests (test code, not reference
implementation). They build on the helpers of `test_m1_route_a`.
"""

from dataclasses import dataclass
from typing import Dict, List

import pytest
from eth_abi import encode
from execution_testing import (
    EOA,
    Account,
    Address,
    Alloc,
    AuthorizationTuple,
    Fork,
    Hash,
    Transaction,
    TransactionLog,
    TransactionReceipt,
)

from .contracts import (
    BEGIN,
    FINISH,
    INITIALIZE,
    MIGRATED_TOPIC,
    REVOKE,
    ROUTE_A,
    code_hash,
    delegation_indicator,
    error,
    migration_check_code,
    migrator_code,
    migrator_initcode,
    verifier_code,
)
from .helpers import MIGRATION_TUPLE, Migration
from .test_m1_route_a import (
    GAS_LIMIT,
    KERNEL,
    Deployment,
    creation_block,
    record,
    recorded,
    selector_word,
)

with_form = pytest.mark.parametrize(
    "via_recorder", [False, True], ids=["direct", "recorded"]
)


def deploy_with_ecrecover(pre: Alloc, ecrecover: Address) -> Deployment:
    """
    Deploy like `test_m1_route_a.deploy`, but from a Migrator initcode
    whose `MigrationCheck` calls `ecrecover` instead of the precompile
    (TEST ONLY); Migrator creates that `MigrationCheck`.
    """
    verifier = pre.deploy_contract(verifier_code())
    template = pre.deploy_contract(KERNEL)
    migrator, check, block = creation_block(pre, migrator_initcode(ecrecover))
    check_hash = code_hash(migration_check_code(migrator, ecrecover))
    return Deployment(verifier, template, migrator, check, check_hash, block)


def migrated_log(
    check: Address, account: Address, adopted_hash: Hash, digest: Hash
) -> TransactionLog:
    """Return `Migrated(account, codeHash, D, route A)` emitted by `check`."""
    return TransactionLog(
        address=check,
        topics=[
            MIGRATED_TOPIC,
            Hash(account, left_padding=True),
            adopted_hash,
        ],
        data=bytes(digest) + ROUTE_A.to_bytes(32, "big"),
    )


def refusal_without_8151(fork: Fork) -> str | None:
    """
    Return the reason a migration that passes P1-P3 is refused: none with
    EIP-8151, `P4Failed` without it.
    """
    return None if fork.is_eip_enabled(8151) else "P4Failed"


def call_with_intent(function: bytes, p: Migration, signature: bytes) -> bytes:
    """Return the calldata of `begin` or `finish(p, ownerSig)`."""
    assert function in (BEGIN, FINISH)
    return function + encode(
        [MIGRATION_TUPLE, "bytes"], [p.abi_tuple(), signature]
    )


def revoke_calldata(digest: Hash) -> bytes:
    """Return the calldata of `revoke(D)`."""
    return REVOKE + bytes(digest)


def initialize_calldata(init: bytes) -> bytes:
    """Return the calldata of `initialize(initData)`."""
    return INITIALIZE + encode(["bytes"], [init])


def kernel_hash() -> Hash:
    """Return the code hash of the reference kernel."""
    return code_hash(KERNEL)


@dataclass(frozen=True)
class Attempt:
    """One call into the owner, sent directly or through the recorder."""

    tx: Transaction
    recorder_post: Dict[int, int]


def attempt(
    *,
    sender: EOA,
    owner: Address,
    recorder: Address,
    calldata: bytes,
    via_recorder: bool,
    reason: str | None,
    authorization: List[AuthorizationTuple] | None = None,
    logs: List[TransactionLog] | None = None,
    to: Address | None = None,
) -> Attempt:
    """
    Return a transaction that calls `to` (by default the owner) with
    `calldata`, directly or through the recorder, and what it must give.

    `reason` is the custom error the call must revert with, or None if it
    must succeed. Direct: the receipt status is 0 on a revert (the revert
    data is not observable), 1 with `logs` on success. Recorded: the
    receipt status is 1 and the recorder holds the outcome; a revert is
    `success 0`, 4 bytes, the error selector.
    """
    target = owner if to is None else to
    expected_logs = [] if reason is not None else (logs or [])
    extra = {"authorization_list": authorization} if authorization else {}
    if via_recorder:
        tx = Transaction(
            sender=sender,
            to=recorder,
            data=record(0, target, calldata),
            gas_limit=GAS_LIMIT,
            expected_receipt=TransactionReceipt(status=1, logs=expected_logs),
            **extra,
        )
        if reason is None:
            outcome = recorded(0, 1, 0, 0)
        else:
            outcome = recorded(0, 0, 4, selector_word(error(reason)))
        return Attempt(tx, outcome)
    tx = Transaction(
        sender=sender,
        to=target,
        data=calldata,
        gas_limit=GAS_LIMIT,
        expected_receipt=TransactionReceipt(
            status=0 if reason is not None else 1, logs=expected_logs
        ),
        **extra,
    )
    return Attempt(tx, {})


def delegated_to(
    target: Address, *, nonce: int, storage: Dict[int, int] | None = None
) -> Account:
    """Return an account that still holds the delegation to `target`."""
    return Account(
        code=delegation_indicator(target),
        nonce=nonce,
        storage=storage if storage is not None else {},
    )


def check_post(deployment: Deployment, ecrecover: Address) -> Dict:
    """
    Return the code that Migrator's and its MigrationCheck's constructors
    must have written, for a deployment from `deploy_with_ecrecover`.
    """
    return {
        deployment.migrator: Account(
            code=migrator_code(
                deployment.migrator, deployment.check, deployment.check_hash
            )
        ),
        deployment.check: Account(
            code=migration_check_code(deployment.migrator, ecrecover)
        ),
    }
