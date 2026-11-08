import os

import oqs

from src.common.hkdf import derive_session_key
from src.common.protocol import KEM_ALG, build_info


def test_ml_kem_interoperability_and_key_derivation():
    """Both peers must obtain the same ML-KEM secret and session key."""
    session_id = os.urandom(16)
    salt = os.urandom(16)

    with oqs.KeyEncapsulation(KEM_ALG) as server_kem:
        public_key = server_kem.generate_keypair()

        with oqs.KeyEncapsulation(KEM_ALG) as device_kem:
            ciphertext, device_secret = device_kem.encap_secret(public_key)

        server_secret = server_kem.decap_secret(ciphertext)

    assert device_secret == server_secret

    info = build_info(session_id)
    device_key = derive_session_key(device_secret, salt, info, length=32)
    server_key = derive_session_key(server_secret, salt, info, length=32)

    assert device_key == server_key
    assert len(device_key) == 32
