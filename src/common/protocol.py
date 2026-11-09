"""Canonical protocol encoding and cryptographic negotiation constants."""

import hashlib

KEM_ALG = "ML-KEM-768"
SIGNATURE_ALG = "ML-DSA-65"
PROTOCOL_VERSION = 2

_SERVER_HELLO_LABEL = b"pqc-iot/server-hello/v2"
_CLIENT_KEM_LABEL = b"pqc-iot/client-kem/v2"
_HKDF_LABEL = b"pqc-iot/traffic-context/v2"


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


def build_client_kem_transcript(ciphertext: bytes) -> bytes:
    """Canonical bytes contributed by the device to the handshake."""
    return _encode_fields(
        _CLIENT_KEM_LABEL,
        KEM_ALG.encode("ascii"),
        ciphertext,
    )


def handshake_transcript_hash(
    server_hello_transcript: bytes,
    client_kem_transcript: bytes,
) -> bytes:
    """Hash the complete handshake transcript for HKDF binding."""
    return hashlib.sha256(
        server_hello_transcript + client_kem_transcript
    ).digest()


def build_info(session_id: bytes, transcript_hash: bytes) -> bytes:
    """Build the context for directional traffic-secret derivation."""
    return _encode_fields(_HKDF_LABEL, session_id, transcript_hash)
