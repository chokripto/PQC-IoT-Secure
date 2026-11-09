import pytest
from cryptography.exceptions import InvalidTag

from src.common.crypto_utils import (
    NonceState,
    aead_decrypt,
    aead_encrypt,
)
from src.common.hkdf import derive_traffic_secrets


def test_aead_roundtrip():
    key = b"\x00" * 32
    nonce = b"\x01" * 12
    aad = b"aad"
    plaintext = b"hello"
    ciphertext = aead_encrypt(key, nonce, plaintext, aad)

    assert aead_decrypt(key, nonce, ciphertext, aad) == plaintext


def test_opposite_direction_key_cannot_decrypt():
    secrets = derive_traffic_secrets(
        b"\x01" * 32,
        b"\x02" * 16,
        b"authenticated-transcript",
    )
    state = NonceState(secrets.device_to_server_nonce_base)
    nonce = state.next_nonce()
    ciphertext = aead_encrypt(
        secrets.device_to_server_key,
        nonce,
        b"telemetry",
        b"device-to-server",
    )

    with pytest.raises(InvalidTag):
        aead_decrypt(
            secrets.server_to_device_key,
            nonce,
            ciphertext,
            b"device-to-server",
        )


def test_nonce_state_rejects_invalid_base():
    with pytest.raises(ValueError):
        NonceState(b"bad")


def test_nonce_state_fails_closed_on_counter_exhaustion():
    state = NonceState(b"base", counter=2**64 - 1)

    with pytest.raises(OverflowError):
        state.next_nonce()
