"""Canonical protocol encoding and cryptographic negotiation constants."""

import hashlib

KEM_ALG = "ML-KEM-768"
SIGNATURE_ALG = "ML-DSA-65"
PROTOCOL_VERSION = 3

_SERVER_HELLO_LABEL = b"pqc-iot/server-hello/v3"
_CLIENT_AUTH_LABEL = b"pqc-iot/client-auth/v3"
_HKDF_LABEL = b"pqc-iot/traffic-context/v3"


def _encode_fields(label: bytes, *fields: bytes) -> bytes:
    """Length-prefix protocol fields to create an unambiguous transcript."""
    encoded = [len(label).to_bytes(4, "big"), label]
    for field in fields:
        encoded.extend((len(field).to_bytes(4, "big"), field))
    return b"".join(encoded)


def identity_key_id(public_key: bytes) -> bytes:
    """Return the full SHA-256 identifier of a provisioned identity key."""
    return hashlib.sha256(public_key).digest()


def build_server_hello_transcript(
    kem_public_key: bytes,
    session_id: bytes,
    salt: bytes,
    identity_key_identifier: bytes,
) -> bytes:
    """Canonical bytes signed by the server identity key."""
    return _encode_fields(
        _SERVER_HELLO_LABEL,
        PROTOCOL_VERSION.to_bytes(2, "big"),
        KEM_ALG.encode("ascii"),
        SIGNATURE_ALG.encode("ascii"),
        identity_key_identifier,
        kem_public_key,
        session_id,
        salt,
    )


def build_client_auth_transcript(
    ciphertext: bytes,
    device_id: str,
    device_key_identifier: bytes,
    server_hello_transcript: bytes,
) -> bytes:
    """Canonical device-authentication contribution to the handshake."""
    return _encode_fields(
        _CLIENT_AUTH_LABEL,
        PROTOCOL_VERSION.to_bytes(2, "big"),
        KEM_ALG.encode("ascii"),
        SIGNATURE_ALG.encode("ascii"),
        device_id.encode("utf-8"),
        device_key_identifier,
        ciphertext,
        hashlib.sha256(server_hello_transcript).digest(),
    )


def handshake_transcript_hash(
    server_hello_transcript: bytes,
    client_auth_transcript: bytes,
) -> bytes:
    """Hash the mutually authenticated handshake for HKDF binding."""
    return hashlib.sha256(
        server_hello_transcript + client_auth_transcript
    ).digest()


def build_info(session_id: bytes, transcript_hash: bytes) -> bytes:
    """Build the context for directional traffic-secret derivation."""
    return _encode_fields(_HKDF_LABEL, session_id, transcript_hash)
