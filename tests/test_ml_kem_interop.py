import os

import oqs

from src.common.hkdf import derive_session_key
from src.common.protocol import (
    KEM_ALG,
    build_client_kem_transcript,
    build_info,
    build_server_hello_transcript,
    handshake_transcript_hash,
    identity_key_id,
)


def test_ml_kem_interoperability_and_transcript_bound_key_derivation():
    """Both peers must obtain the same secret and transcript-bound key."""
    session_id = os.urandom(16)
    salt = os.urandom(16)
    server_nonce_prefix = os.urandom(4)
    client_nonce_prefix = os.urandom(4)
    identity_public_key = os.urandom(1952)
    key_id = identity_key_id(identity_public_key)

    with oqs.KeyEncapsulation(KEM_ALG) as server_kem:
        public_key = server_kem.generate_keypair()
        server_transcript = build_server_hello_transcript(
            public_key,
            session_id,
            salt,
            server_nonce_prefix,
            key_id,
        )

        with oqs.KeyEncapsulation(KEM_ALG) as device_kem:
            ciphertext, device_secret = device_kem.encap_secret(public_key)

        server_secret = server_kem.decap_secret(ciphertext)

    client_transcript = build_client_kem_transcript(
        ciphertext, client_nonce_prefix
    )
    transcript_hash = handshake_transcript_hash(
        server_transcript, client_transcript
    )
    info = build_info(session_id, transcript_hash)

    device_key = derive_session_key(device_secret, salt, info, length=32)
    server_key = derive_session_key(server_secret, salt, info, length=32)

    assert device_secret == server_secret
    assert device_key == server_key
    assert len(device_key) == 32
