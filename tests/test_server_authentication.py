import os

import oqs

from src.common.protocol import (
    KEM_ALG,
    SIGNATURE_ALG,
    build_server_hello_transcript,
    identity_key_id,
)


def _server_transcript(identity_public_key: bytes, salt: bytes) -> bytes:
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public_key = kem.generate_keypair()

    return build_server_hello_transcript(
        kem_public_key,
        os.urandom(16),
        salt,
        os.urandom(4),
        identity_key_id(identity_public_key),
    )


def test_valid_server_identity_signature_is_accepted():
    with oqs.Signature(SIGNATURE_ALG) as signer:
        public_key = signer.generate_keypair()
        transcript = _server_transcript(public_key, os.urandom(16))
        signature = signer.sign(transcript)

    with oqs.Signature(SIGNATURE_ALG) as verifier:
        assert verifier.verify(transcript, signature, public_key)


def test_modified_transcript_is_rejected():
    with oqs.Signature(SIGNATURE_ALG) as signer:
        public_key = signer.generate_keypair()
        transcript = _server_transcript(public_key, os.urandom(16))
        signature = signer.sign(transcript)
        modified_transcript = transcript[:-1] + bytes([transcript[-1] ^ 1])

    with oqs.Signature(SIGNATURE_ALG) as verifier:
        assert not verifier.verify(
            modified_transcript, signature, public_key
        )


def test_modified_signature_is_rejected():
    with oqs.Signature(SIGNATURE_ALG) as signer:
        public_key = signer.generate_keypair()
        transcript = _server_transcript(public_key, os.urandom(16))
        signature = signer.sign(transcript)
        modified_signature = signature[:-1] + bytes([signature[-1] ^ 1])

    with oqs.Signature(SIGNATURE_ALG) as verifier:
        assert not verifier.verify(
            transcript, modified_signature, public_key
        )


def test_signature_from_unpinned_identity_is_rejected():
    with oqs.Signature(SIGNATURE_ALG) as trusted_signer:
        trusted_public_key = trusted_signer.generate_keypair()

    with oqs.Signature(SIGNATURE_ALG) as attacker_signer:
        attacker_signer.generate_keypair()
        transcript = _server_transcript(
            trusted_public_key, os.urandom(16)
        )
        attacker_signature = attacker_signer.sign(transcript)

    with oqs.Signature(SIGNATURE_ALG) as verifier:
        assert not verifier.verify(
            transcript, attacker_signature, trusted_public_key
        )
