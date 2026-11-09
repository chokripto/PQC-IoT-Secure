import hmac
import os
import socket

import oqs

from src.common.crypto_utils import (
    NonceState,
    aead_decrypt,
    aead_encrypt,
    b64d,
    b64e,
    short_fingerprint,
)
from src.common.hkdf import derive_session_key
from src.common.identity import load_pinned_server_public_key
from src.common.message import recv_frame, send_frame
from src.common.protocol import (
    KEM_ALG,
    PROTOCOL_VERSION,
    SIGNATURE_ALG,
    build_client_kem_transcript,
    build_info,
    build_server_hello_transcript,
    handshake_transcript_hash,
    identity_key_id,
)


HOST = "server"
PORT = 9000


def run_device() -> None:
    pinned_identity_key = load_pinned_server_public_key()
    pinned_key_id = identity_key_id(pinned_identity_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[device] Connected to {HOST}:{PORT}")

        hello = recv_frame(s)
        if hello.get("type") != "server_hello":
            raise ValueError(f"Unexpected message type: {hello.get('type')}")
        if hello.get("protocol_version") != PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol version")
        if hello.get("kem_alg") != KEM_ALG:
            raise ValueError(
                f"Unsupported KEM: {hello.get('kem_alg')!r}; expected {KEM_ALG}"
            )
        if hello.get("identity_alg") != SIGNATURE_ALG:
            raise ValueError(
                f"Unsupported identity algorithm: "
                f"{hello.get('identity_alg')!r}"
            )

        kem_public_key = b64d(hello["pk_b64"])
        session_id = b64d(hello["session_id_b64"])
        salt = b64d(hello["salt_b64"])
        server_nonce_prefix = b64d(hello["server_nonce_prefix_b64"])
        received_key_id = b64d(hello["identity_key_id_b64"])
        server_signature = b64d(hello["signature_b64"])

        if not hmac.compare_digest(received_key_id, pinned_key_id):
            raise ValueError(
                "Server identity does not match the provisioned key"
            )

        server_transcript = build_server_hello_transcript(
            kem_public_key,
            session_id,
            salt,
            server_nonce_prefix,
            received_key_id,
        )
        with oqs.Signature(SIGNATURE_ALG) as verifier:
            if not verifier.verify(
                server_transcript,
                server_signature,
                pinned_identity_key,
            ):
                raise ValueError(
                    "Invalid ML-DSA signature on server handshake"
                )

        # The server identity is authenticated before KEM encapsulation.
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            ct, shared_secret = kem.encap_secret(kem_public_key)

        client_nonce_prefix = os.urandom(4)
        client_transcript = build_client_kem_transcript(
            ct, client_nonce_prefix
        )
        transcript_hash = handshake_transcript_hash(
            server_transcript, client_transcript
        )
        info = build_info(session_id, transcript_hash)
        session_key = derive_session_key(
            shared_secret, salt=salt, info=info, length=32
        )

        print("[device] Server identity authenticated.")
        print(f"[device] identity_key_id={pinned_key_id.hex()[:20]}")
        print(
            f"[device] transcript(fp)="
            f"{short_fingerprint(transcript_hash)}"
        )

        send_frame(
            s,
            {
                "type": "client_kem",
                "kem_alg": KEM_ALG,
                "ct_b64": b64e(ct),
                "client_nonce_prefix_b64": b64e(client_nonce_prefix),
            },
        )

        send_state = NonceState(prefix4=client_nonce_prefix, counter=0)
        recv_state = NonceState(prefix4=server_nonce_prefix, counter=0)

        ack = recv_frame(s)
        if ack.get("type") != "session_ack":
            raise ValueError(f"Unexpected message type: {ack.get('type')}")

        nonce_ack = b64d(ack["nonce_b64"])
        aad_ack = b64d(ack["aad_b64"])
        ct_ack = b64d(ack["ciphertext_b64"])

        expected_nonce_ack = recv_state.next_nonce()
        if not hmac.compare_digest(nonce_ack, expected_nonce_ack):
            raise ValueError("[device] Nonce mismatch in session_ack.")

        pt_ack = aead_decrypt(session_key, nonce_ack, ct_ack, aad_ack)
        print(
            "[device] Session ack decrypted: "
            f"{pt_ack.decode('utf-8', errors='replace')}"
        )

        msg = "temperature=23.7C; humidity=41%"
        aad = b"app-data|device->server"
        nonce = send_state.next_nonce()
        ct_msg = aead_encrypt(
            session_key, nonce, msg.encode("utf-8"), aad
        )

        send_frame(
            s,
            {
                "type": "data",
                "nonce_b64": b64e(nonce),
                "aad_b64": b64e(aad),
                "ciphertext_b64": b64e(ct_msg),
            },
        )
        print("[device] Encrypted message sent.")

        resp = recv_frame(s)
        if resp.get("type") != "data":
            raise ValueError(f"Unexpected message type: {resp.get('type')}")

        nonce_in = b64d(resp["nonce_b64"])
        aad_in = b64d(resp["aad_b64"])
        ct_in = b64d(resp["ciphertext_b64"])

        expected_nonce_in = recv_state.next_nonce()
        if not hmac.compare_digest(nonce_in, expected_nonce_in):
            raise ValueError(
                "[device] Nonce mismatch in response "
                "(possible replay/out-of-order)."
            )

        pt_in = aead_decrypt(session_key, nonce_in, ct_in, aad_in)
        print(
            "[device] Decrypted server response: "
            f"{pt_in.decode('utf-8', errors='replace')}"
        )
        print("[device] Done.")


if __name__ == "__main__":
    run_device()
