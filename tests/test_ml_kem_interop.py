import os

import oqs

from src.common.hkdf import derive_traffic_secrets
from src.common.protocol import (
    KEM_ALG,
    build_client_kem_transcript,
    build_info,
    build_server_hello_transcript,
    handshake_transcript_hash,
    identity_key_id,
)


def test_ml_kem_interoperability_and_directional_traffic_secrets():
    """Both peers must derive identical, role-separated traffic secrets."""
    session_id = os.urandom(16)
    salt = os.urandom(16)
    identity_public_key = os.urandom(1952)
    key_id = identity_key_id(identity_public_key)

    with oqs.KeyEncapsulation(KEM_ALG) as server_kem:
        public_key = server_kem.generate_keypair()
        server_transcript = build_server_hello_transcript(
            public_key,
            session_id,
            salt,
            key_id,
        )

        with oqs.KeyEncapsulation(KEM_ALG) as device_kem:
            ciphertext, device_secret = device_kem.encap_secret(public_key)

        server_secret = server_kem.decap_secret(ciphertext)

    client_transcript = build_client_kem_transcript(ciphertext)
    transcript_hash = handshake_transcript_hash(
        server_transcript, client_transcript
    )
    context = build_info(session_id, transcript_hash)

    device_traffic = derive_traffic_secrets(
        device_secret, salt, context
    )
    server_traffic = derive_traffic_secrets(
        server_secret, salt, context
    )

    assert device_secret == server_secret
    assert device_traffic == server_traffic
    assert (
        device_traffic.device_to_server_key
        != device_traffic.server_to_device_key
    )
    assert (
        device_traffic.device_to_server_nonce_base
        != device_traffic.server_to_device_nonce_base
    )
