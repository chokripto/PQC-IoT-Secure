"""Strict schemas and size limits for untrusted protocol messages."""

from typing import Any

from src.common.crypto_utils import b64d
from src.common.message import ProtocolError
from src.common.protocol import KEM_ALG, PROTOCOL_VERSION, SIGNATURE_ALG

ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_CIPHERTEXT_BYTES = 1088
IDENTITY_KEY_ID_BYTES = 32
SESSION_ID_BYTES = 16
HKDF_SALT_BYTES = 16
AES_GCM_NONCE_BYTES = 12
MAX_SIGNATURE_BYTES = 4096
MAX_AAD_BYTES = 128
MAX_ENCRYPTED_PAYLOAD_BYTES = 16 * 1024 + 16


def _require_schema(
    message: dict[str, Any],
    message_type: str,
    fields: dict[str, type],
) -> None:
    expected = {"type", *fields}
    actual = set(message)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ProtocolError(
            f"Invalid {message_type} schema; missing={missing}, unknown={unknown}"
        )
    if message["type"] != message_type:
        raise ProtocolError(f"Expected {message_type} message")
    for field, expected_type in fields.items():
        if type(message[field]) is not expected_type:
            raise ProtocolError(f"Field {field} has an invalid type")


def _decode_exact(message: dict[str, Any], field: str, length: int) -> bytes:
    try:
        value = b64d(message[field])
    except ValueError as exc:
        raise ProtocolError(f"Field {field} is not valid Base64") from exc
    if len(value) != length:
        raise ProtocolError(f"Field {field} must decode to {length} bytes")
    return value


def _decode_bounded(
    message: dict[str, Any], field: str, minimum: int, maximum: int
) -> bytes:
    try:
        value = b64d(message[field])
    except ValueError as exc:
        raise ProtocolError(f"Field {field} is not valid Base64") from exc
    if not minimum <= len(value) <= maximum:
        raise ProtocolError(
            f"Field {field} must decode to {minimum}..{maximum} bytes"
        )
    return value


def validate_server_hello(
    message: dict[str, Any],
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    fields = {
        "protocol_version": int,
        "kem_alg": str,
        "identity_alg": str,
        "identity_key_id_b64": str,
        "pk_b64": str,
        "session_id_b64": str,
        "salt_b64": str,
        "signature_b64": str,
    }
    _require_schema(message, "server_hello", fields)
    if message["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("Unsupported protocol version")
    if message["kem_alg"] != KEM_ALG:
        raise ProtocolError("Unsupported KEM algorithm")
    if message["identity_alg"] != SIGNATURE_ALG:
        raise ProtocolError("Unsupported identity algorithm")

    return (
        _decode_exact(message, "pk_b64", ML_KEM_768_PUBLIC_KEY_BYTES),
        _decode_exact(message, "session_id_b64", SESSION_ID_BYTES),
        _decode_exact(message, "salt_b64", HKDF_SALT_BYTES),
        _decode_exact(message, "identity_key_id_b64", IDENTITY_KEY_ID_BYTES),
        _decode_bounded(message, "signature_b64", 1, MAX_SIGNATURE_BYTES),
    )


def validate_client_auth(
    message: dict[str, Any],
) -> tuple[bytes, str, bytes, bytes]:
    _require_schema(
        message,
        "client_auth",
        {
            "kem_alg": str,
            "identity_alg": str,
            "device_id": str,
            "device_key_id_b64": str,
            "ct_b64": str,
            "signature_b64": str,
        },
    )
    if message["kem_alg"] != KEM_ALG:
        raise ProtocolError("KEM algorithm mismatch")
    if message["identity_alg"] != SIGNATURE_ALG:
        raise ProtocolError("Unsupported device identity algorithm")
    device_id = message["device_id"]
    if not device_id or len(device_id.encode("utf-8")) > 64:
        raise ProtocolError("Device ID must contain 1..64 UTF-8 bytes")
    return (
        _decode_exact(message, "ct_b64", ML_KEM_768_CIPHERTEXT_BYTES),
        device_id,
        _decode_exact(
            message, "device_key_id_b64", IDENTITY_KEY_ID_BYTES
        ),
        _decode_bounded(
            message, "signature_b64", 1, MAX_SIGNATURE_BYTES
        ),
    )


def validate_encrypted_message(
    message: dict[str, Any], message_type: str
) -> tuple[bytes, bytes, bytes]:
    _require_schema(
        message,
        message_type,
        {"nonce_b64": str, "aad_b64": str, "ciphertext_b64": str},
    )
    nonce = _decode_exact(message, "nonce_b64", AES_GCM_NONCE_BYTES)
    aad = _decode_bounded(message, "aad_b64", 1, MAX_AAD_BYTES)
    ciphertext = _decode_bounded(
        message,
        "ciphertext_b64",
        16,
        MAX_ENCRYPTED_PAYLOAD_BYTES,
    )
    return nonce, aad, ciphertext
