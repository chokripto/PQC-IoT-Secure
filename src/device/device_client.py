import hmac
import socket

import oqs

from src.common.crypto_utils import (
    NonceState,
    aead_decrypt,
    aead_encrypt,
    b64e,
    short_fingerprint,
)
from src.common.hkdf import derive_traffic_secrets
from src.common.identity import load_pinned_server_public_key
from src.common.message import recv_frame, send_frame
from src.common.protocol import (
    KEM_ALG,
    SIGNATURE_ALG,
    build_client_kem_transcript,
    build_info,
    build_server_hello_transcript,
    handshake_transcript_hash,
    identity_key_id,
)
from src.common.validation import (
    validate_encrypted_message,
    validate_server_hello,
)

HOST = "server"
PORT = 9000
CONNECT_TIMEOUT_SECONDS = 5
IO_TIMEOUT_SECONDS = 10


def run_device() -> None:
    pinned_identity_key = load_pinned_server_public_key()
    pinned_key_id = identity_key_id(pinned_identity_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(CONNECT_TIMEOUT_SECONDS)
        s.connect((HOST, PORT))
        s.settimeout(IO_TIMEOUT_SECONDS)
        print(f"[device] Connected to {HOST}:{PORT}")

        hello = recv_frame(s)
        (
            kem_public_key,
            session_id,
            salt,
            received_key_id,
            server_signature,
        ) = validate_server_hello(hello)

        if not hmac.compare_digest(received_key_id, pinned_key_id):
            raise ValueError(
                "Server identity does not match the provisioned key"
            )

        server_transcript = build_server_hello_transcript(
            kem_public_key,
            session_id,
            salt,
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

        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            ciphertext, shared_secret = kem.encap_secret(kem_public_key)

        client_transcript = build_client_kem_transcript(ciphertext)
        transcript_hash = handshake_transcript_hash(
            server_transcript, client_transcript
        )
        context = build_info(session_id, transcript_hash)
        traffic = derive_traffic_secrets(shared_secret, salt, context)

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
                "ct_b64": b64e(ciphertext),
            },
        )

        send_state = NonceState(traffic.device_to_server_nonce_base)
        recv_state = NonceState(traffic.server_to_device_nonce_base)

        ack = recv_frame(s)
        nonce_ack, aad_ack, ciphertext_ack = validate_encrypted_message(
            ack, "session_ack"
        )

        expected_nonce_ack = recv_state.next_nonce()
        if not hmac.compare_digest(nonce_ack, expected_nonce_ack):
            raise ValueError("[device] Nonce mismatch in session_ack.")

        plaintext_ack = aead_decrypt(
            traffic.server_to_device_key,
            nonce_ack,
            ciphertext_ack,
            aad_ack,
        )
        print(
            "[device] Session ack decrypted: "
            f"{plaintext_ack.decode('utf-8', errors='replace')}"
        )

        message = "temperature=23.7C; humidity=41%"
        aad = b"app-data|device->server"
        nonce = send_state.next_nonce()
        encrypted_message = aead_encrypt(
            traffic.device_to_server_key,
            nonce,
            message.encode("utf-8"),
            aad,
        )

        send_frame(
            s,
            {
                "type": "data",
                "nonce_b64": b64e(nonce),
                "aad_b64": b64e(aad),
                "ciphertext_b64": b64e(encrypted_message),
            },
        )
        print("[device] Encrypted message sent.")

        response = recv_frame(s)
        nonce_in, aad_in, ciphertext_in = validate_encrypted_message(
            response, "data"
        )

        expected_nonce_in = recv_state.next_nonce()
        if not hmac.compare_digest(nonce_in, expected_nonce_in):
            raise ValueError(
                "[device] Nonce mismatch in response "
                "(possible replay/out-of-order)."
            )

        plaintext_in = aead_decrypt(
            traffic.server_to_device_key,
            nonce_in,
            ciphertext_in,
            aad_in,
        )
        print(
            "[device] Decrypted server response: "
            f"{plaintext_in.decode('utf-8', errors='replace')}"
        )
        print("[device] Done.")


if __name__ == "__main__":
    run_device()
