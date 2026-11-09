import hmac
import os
import socket
from typing import Any

import oqs

from src.common.crypto_utils import (
    NonceState,
    aead_decrypt,
    aead_encrypt,
    b64d,
    b64e,
    short_fingerprint,
)
from src.common.hkdf import derive_traffic_secrets
from src.common.identity import load_server_identity_keypair
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

HOST = "0.0.0.0"
PORT = 9000


def run_server() -> None:
    if not oqs.is_kem_enabled(KEM_ALG):
        raise RuntimeError(f"{KEM_ALG} is not enabled in this OQS build")
    if not oqs.is_sig_enabled(SIGNATURE_ALG):
        raise RuntimeError(
            f"{SIGNATURE_ALG} is not enabled in this OQS build"
        )

    identity_public_key, identity_secret_key = (
        load_server_identity_keypair()
    )
    server_key_id = identity_key_id(identity_public_key)

    with oqs.Signature(
        SIGNATURE_ALG, identity_secret_key
    ) as identity_signer:
        expected_public_length = identity_signer.details["length_public_key"]
        if len(identity_public_key) != expected_public_length:
            raise RuntimeError(
                "Provisioned ML-DSA public key has an invalid length"
            )

        key_check_message = b"pqc-iot/server-identity-key-check/v1"
        key_check_signature = identity_signer.sign(key_check_message)
        if not identity_signer.verify(
            key_check_message, key_check_signature, identity_public_key
        ):
            raise RuntimeError(
                "Provisioned ML-DSA public and private keys do not match"
            )

        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            kem_public_key = kem.generate_keypair()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen(1)
                print(f"[server] Listening on {HOST}:{PORT}")

                conn, addr = s.accept()
                with conn:
                    print(f"[server] Connection from {addr}")

                    session_id = os.urandom(16)
                    salt = os.urandom(16)

                    server_transcript = build_server_hello_transcript(
                        kem_public_key,
                        session_id,
                        salt,
                        server_key_id,
                    )
                    server_signature = identity_signer.sign(
                        server_transcript
                    )

                    send_frame(
                        conn,
                        {
                            "type": "server_hello",
                            "protocol_version": PROTOCOL_VERSION,
                            "kem_alg": KEM_ALG,
                            "identity_alg": SIGNATURE_ALG,
                            "identity_key_id_b64": b64e(server_key_id),
                            "pk_b64": b64e(kem_public_key),
                            "session_id_b64": b64e(session_id),
                            "salt_b64": b64e(salt),
                            "signature_b64": b64e(server_signature),
                        },
                    )

                    message = recv_frame(conn)
                    if message.get("type") != "client_kem":
                        raise ValueError(
                            "Unexpected message type: "
                            f"{message.get('type')}"
                        )
                    if message.get("kem_alg") != KEM_ALG:
                        raise ValueError(
                            "KEM algorithm mismatch: "
                            f"{message.get('kem_alg')!r}"
                        )

                    ciphertext = b64d(message["ct_b64"])
                    shared_secret = kem.decap_secret(ciphertext)

                    client_transcript = build_client_kem_transcript(
                        ciphertext
                    )
                    transcript_hash = handshake_transcript_hash(
                        server_transcript, client_transcript
                    )
                    context = build_info(session_id, transcript_hash)
                    traffic = derive_traffic_secrets(
                        shared_secret, salt, context
                    )

                    print("[server] Authenticated session established.")
                    print(
                        f"[server] identity_key_id="
                        f"{server_key_id.hex()[:20]}"
                    )
                    print(
                        f"[server] transcript(fp)="
                        f"{short_fingerprint(transcript_hash)}"
                    )

                    send_state = NonceState(
                        traffic.server_to_device_nonce_base
                    )
                    recv_state = NonceState(
                        traffic.device_to_server_nonce_base
                    )

                    aad = b"session-ack|server"
                    nonce = send_state.next_nonce()
                    ciphertext_ack = aead_encrypt(
                        traffic.server_to_device_key,
                        nonce,
                        b"OK",
                        aad,
                    )

                    send_frame(
                        conn,
                        {
                            "type": "session_ack",
                            "nonce_b64": b64e(nonce),
                            "aad_b64": b64e(aad),
                            "ciphertext_b64": b64e(ciphertext_ack),
                        },
                    )

                    data_message: dict[str, Any] = recv_frame(conn)
                    if data_message.get("type") != "data":
                        raise ValueError(
                            "Unexpected message type: "
                            f"{data_message.get('type')}"
                        )

                    nonce_in = b64d(data_message["nonce_b64"])
                    aad_in = b64d(data_message["aad_b64"])
                    ciphertext_in = b64d(
                        data_message["ciphertext_b64"]
                    )

                    expected_nonce = recv_state.next_nonce()
                    if not hmac.compare_digest(nonce_in, expected_nonce):
                        raise ValueError(
                            "[server] Nonce mismatch "
                            "(possible replay/out-of-order)."
                        )

                    plaintext = aead_decrypt(
                        traffic.device_to_server_key,
                        nonce_in,
                        ciphertext_in,
                        aad_in,
                    )
                    print(
                        "[server] Decrypted message from device: "
                        f"{plaintext.decode('utf-8', errors='replace')}"
                    )

                    response = b"ACK: message received securely"
                    aad_out = b"app-data|server->device"
                    nonce_out = send_state.next_nonce()
                    ciphertext_out = aead_encrypt(
                        traffic.server_to_device_key,
                        nonce_out,
                        response,
                        aad_out,
                    )

                    send_frame(
                        conn,
                        {
                            "type": "data",
                            "nonce_b64": b64e(nonce_out),
                            "aad_b64": b64e(aad_out),
                            "ciphertext_b64": b64e(ciphertext_out),
                        },
                    )

                    print("[server] Response sent. Closing connection.")


if __name__ == "__main__":
    run_server()
