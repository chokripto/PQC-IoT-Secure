import base64
import binascii
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    if not isinstance(s, str):
        raise ValueError("Base64 value must be a string")
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("Invalid Base64 encoding") from exc


def short_fingerprint(data: bytes, n: int = 10) -> str:
    """Return a demo-only hash fingerprint, never the secret itself."""
    return hashlib.sha256(data).hexdigest()[: 2 * n]


@dataclass
class NonceState:
    """Generate unique 96-bit AES-GCM nonces from a base and counter."""

    prefix4: bytes
    counter: int = 0

    def __post_init__(self) -> None:
        if len(self.prefix4) != 4:
            raise ValueError("AES-GCM nonce base must be exactly 4 bytes")
        if not 0 <= self.counter <= (2**64 - 1):
            raise ValueError("Nonce counter is outside the uint64 range")

    def next_nonce(self) -> bytes:
        if self.counter == 2**64 - 1:
            raise OverflowError("AES-GCM nonce counter exhausted")
        self.counter += 1
        return self.prefix4 + self.counter.to_bytes(8, "big")


def aead_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes
) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
