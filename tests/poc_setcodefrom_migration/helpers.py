"""
Off-chain helpers of the PoC: EIP-712 digests, signing (secp256k1 and P256)
and stand-ins for the #3860 test helpers on the tree without EIP-8151.

The EIP-712 name and version, the scope bits and the storage slots are
choices of this PoC, not decisions of the ERC (the draft leaves them TBD).
"""

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from eth_abi import encode
from execution_testing import EOA, Address, Bytes, Fork, Hash
from spec256k1 import PrivateKey

DOMAIN_NAME = b"SETCODEFROM Adoption PoC"
DOMAIN_VERSION = b"0"

# Scope bits, aligned with EIP-8141 APPROVE_PAYMENT and APPROVE_EXECUTION.
SCOPE_PAYMENT = 0x1
SCOPE_EXECUTION = 0x2


def keccak(data: bytes) -> Hash:
    """Return the keccak256 of `data`."""
    return Hash(Bytes(data).keccak256())


def selector(signature: str) -> bytes:
    """Return the 4-byte ABI selector of a function or error signature."""
    return bytes(keccak(signature.encode()))[:4]


DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract)"
)
NAME_HASH = keccak(DOMAIN_NAME)
VERSION_HASH = keccak(DOMAIN_VERSION)
MIGRATION_TYPEHASH = keccak(
    b"Migration(address source,bytes32 codeHash,bytes32 initDataHash,"
    b"uint256 deadline,address executor,address check)"
)
REGISTRATION_TYPEHASH = keccak(
    b"Registration(address verifier,bytes32 keyHash,uint8 scope)"
)
ACCOUNT_MESSAGE_TYPEHASH = keccak(b"AccountMessage(bytes32 hash)")

MIGRATION_TUPLE = "(address,bytes32,bytes32,uint256,address,address)"


def domain_separator(chain_id: int, account: Address) -> Hash:
    """Return the PoC domain separator bound to `account`."""
    return keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, chain_id, str(account)],
        )
    )


def typed_digest(chain_id: int, account: Address, struct_hash: Hash) -> Hash:
    """Return the EIP-712 digest of `struct_hash` under the PoC domain."""
    return keccak(
        b"\x19\x01" + domain_separator(chain_id, account) + struct_hash
    )


def registration_digest(
    chain_id: int,
    account: Address,
    verifier: Address,
    key: bytes,
    scope: int,
) -> Hash:
    """Return the `Registration` digest of an authority of `account`."""
    struct_hash = keccak(
        encode(
            ["bytes32", "address", "bytes32", "uint8"],
            [REGISTRATION_TYPEHASH, str(verifier), keccak(key), scope],
        )
    )
    return typed_digest(chain_id, account, struct_hash)


def account_message_digest(
    chain_id: int, account: Address, message_hash: Hash
) -> Hash:
    """Return the `AccountMessage` digest that ERC-1271 verifies."""
    struct_hash = keccak(
        encode(
            ["bytes32", "bytes32"], [ACCOUNT_MESSAGE_TYPEHASH, message_hash]
        )
    )
    return typed_digest(chain_id, account, struct_hash)


@dataclass(frozen=True)
class Migration:
    """The signed `Migration` struct."""

    source: Address
    code_hash: Hash
    init_data_hash: Hash
    deadline: int
    executor: Address
    check: Address

    def abi_tuple(self) -> tuple[Any, ...]:
        """Return the struct as an `eth_abi` tuple."""
        return (
            str(self.source),
            bytes(self.code_hash),
            bytes(self.init_data_hash),
            self.deadline,
            str(self.executor),
            str(self.check),
        )

    def digest(self, chain_id: int, account: Address) -> Hash:
        """Return `D`, the digest the old key signs."""
        struct_hash = keccak(
            encode(
                ["bytes32", MIGRATION_TUPLE],
                [MIGRATION_TYPEHASH, self.abi_tuple()],
            )
        )
        return typed_digest(chain_id, account, struct_hash)


def init_data(
    verifier: Address, key: bytes, scope: int, proof: bytes
) -> bytes:
    """Return `initData`: abi.encode(verifier, key, scope, proof)."""
    return encode(
        ["address", "bytes", "uint8", "bytes"],
        [str(verifier), key, scope, proof],
    )


def sign_digest(signer: EOA, digest: Hash) -> tuple[int, int, int]:
    """
    Sign `digest` as is and return the ecrecover `(v, r, s)`.

    Use `EOA.sign_digest` from #3860 where the tree has it; the tree without
    EIP-8151 does not, so sign the same way here.
    """
    if hasattr(signer, "sign_digest"):
        return signer.sign_digest(digest)
    assert signer.key is not None
    signature = PrivateKey(signer.key).sign_recoverable(digest)
    v = signature[64] + 27
    r = int.from_bytes(signature[0:32], byteorder="big")
    s = int.from_bytes(signature[32:64], byteorder="big")
    return v, r, s


def owner_signature(signer: EOA, digest: Hash) -> bytes:
    """Return the 65-byte `r ‖ s ‖ v` signature of `digest`."""
    v, r, s = sign_digest(signer, digest)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])


def ecrecover_gas(fork: Fork, *, recovered: bool, address_warm: bool) -> int:
    """
    Return the ecrecover charge; the tree without EIP-8151 lacks
    `fork.ecrecover_gas` and charges the flat precompile fee.
    """
    if hasattr(fork, "ecrecover_gas"):
        return fork.ecrecover_gas(
            recovered=recovered, address_warm=address_warm
        )
    return fork.gas_costs().PRECOMPILE_ECRECOVER


class P256Key:
    """A P256 key whose signatures are deterministic (RFC 6979)."""

    def __init__(self, secret: int) -> None:
        """Derive the key pair from `secret`."""
        self._key = ec.derive_private_key(secret, ec.SECP256R1())
        numbers = self._key.public_key().public_numbers()
        self.public_key = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(
            32, "big"
        )

    def sign(self, digest: Hash) -> bytes:
        """Return the 64-byte `r ‖ s` signature of the 32-byte `digest`."""
        der = self._key.sign(
            bytes(digest),
            ec.ECDSA(
                utils.Prehashed(hashes.SHA256()), deterministic_signing=True
            ),
        )
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
