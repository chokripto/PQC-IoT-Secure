import json
import socket
import struct

import pytest

from src.common.crypto_utils import b64e
from src.common.message import MAX_FRAME_SIZE, ProtocolError, recv_frame
from src.common.protocol import KEM_ALG
from src.common.validation import (
    ML_KEM_768_CIPHERTEXT_BYTES,
    validate_client_auth,
    validate_encrypted_message,
)


def _socket_frame(payload: bytes) -> socket.socket:
    sender, receiver = socket.socketpair()
    sender.sendall(struct.pack("!I", len(payload)) + payload)
    sender.close()
    return receiver


def test_rejects_oversized_frame_before_payload_read():
    sender, receiver = socket.socketpair()
    sender.sendall(struct.pack("!I", MAX_FRAME_SIZE + 1))
    sender.close()
    with receiver, pytest.raises(
        ProtocolError, match="Invalid frame length"
    ):
        recv_frame(receiver)


@pytest.mark.parametrize("payload", [b"[]", b"not-json", b'{"x":NaN}'])
def test_rejects_non_object_or_invalid_json(payload):
    with _socket_frame(payload) as receiver, pytest.raises(ProtocolError):
        recv_frame(receiver)


def test_rejects_duplicate_json_fields():
    payload = b'{"type":"data","type":"client_kem"}'
    with _socket_frame(payload) as receiver, pytest.raises(
        ProtocolError, match="Duplicate JSON field"
    ):
        recv_frame(receiver)


def test_socket_timeout_fails_closed():
    sender, receiver = socket.socketpair()
    receiver.settimeout(0.01)
    try:
        with pytest.raises(ProtocolError, match="Timed out"):
            recv_frame(receiver)
    finally:
        sender.close()
        receiver.close()


def _valid_client_auth() -> dict[str, object]:
    return {
        "type": "client_auth",
        "kem_alg": KEM_ALG,
        "identity_alg": "ML-DSA-65",
        "device_id": "device-001",
        "device_key_id_b64": b64e(b"k" * 32),
        "ct_b64": b64e(b"x" * ML_KEM_768_CIPHERTEXT_BYTES),
        "signature_b64": b64e(b"s" * 64),
    }


def test_client_auth_rejects_unknown_fields():
    message = _valid_client_auth()
    message["unexpected"] = "value"
    with pytest.raises(ProtocolError, match="unknown"):
        validate_client_auth(message)


def test_client_auth_rejects_invalid_ciphertext_length():
    message = _valid_client_auth()
    message["ct_b64"] = b64e(b"short")
    with pytest.raises(ProtocolError, match="1088 bytes"):
        validate_client_auth(message)


def test_encrypted_message_rejects_invalid_nonce_and_oversized_aad():
    base = {
        "type": "data",
        "nonce_b64": b64e(b"x" * 11),
        "aad_b64": b64e(b"aad"),
        "ciphertext_b64": b64e(b"x" * 16),
    }
    with pytest.raises(ProtocolError, match="12 bytes"):
        validate_encrypted_message(base, "data")

    base["nonce_b64"] = b64e(b"x" * 12)
    base["aad_b64"] = b64e(b"x" * 129)
    with pytest.raises(ProtocolError, match="1..128 bytes"):
        validate_encrypted_message(base, "data")


def test_frame_json_roundtrip_is_an_object():
    payload = json.dumps({"type": "test"}).encode()
    with _socket_frame(payload) as receiver:
        assert recv_frame(receiver) == {"type": "test"}
