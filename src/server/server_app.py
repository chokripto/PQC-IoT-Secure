import os
import socket
from typing import Any, Dict

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
from src.common.message import recv_frame, send_frame
from src.common.protocol import KEM_ALG, build_info

HOST = "0.0.0.0"
PORT = 9000


def run_server() -> None:
    if not oqs.is_kem_enabled(KEM_ALG):
        raise RuntimeError(f"{KEM_ALG} is not enabled in this OQS build")

    # The KEM object owns the ephemeral secret key for this server session.
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        pk = kem.generate_keypair()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            print(f"[server] Listening on {HOST}:{PORT}")

            conn, addr = s.accept()
            with conn:
                print(f"[server] Connection from {addr}")

                session_id = os.urandom(16)
                salt = os.urandom(16)
                server_nonce_prefix = os.urandom(4)

                send_frame(
                    conn,
                    {
                        "type": "server_hello",
                        "kem_alg": KEM_ALG,
                        "pk_b64": b64e(pk),
                        "session_id_b64": b64e(session_id),
                        "salt_b64": b64e(salt),
                        "server_nonce_prefix_b64": b64e(server_nonce_prefix),
                    },
                )

                msg = recv_frame(conn)
                if msg.get("type") != "client_kem":
                    raise ValueError(f"Unexpected message type: {msg.get('type')}")
                if msg.get("kem_alg") != KEM_ALG:
                    raise ValueError(
                        f"KEM algorithm mismatch: {msg.get('kem_alg')!r}"
                    )

                ct = b64d(msg["ct_b64"])
                client_nonce_prefix = b64d(msg["client_nonce_prefix_b64"])
                shared_secret = kem.decap_secret(ct)

                info = build_info(session_id)
                session_key = derive_session_key(
                    shared_secret, salt=salt, info=info, length=32
                )

                print("[server] Session established.")
                print(
                    f"[server] session_id(fp)={short_fingerprint(session_id)} "
                    f"salt(fp)={short_fingerprint(salt)}"
                )
                print(
                    f"[server] ss(fp)={short_fingerprint(shared_secret)} "
                    f"key(fp)={short_fingerprint(session_key)}"
                )

                send_state = NonceState(prefix4=server_nonce_prefix, counter=0)
                recv_state = NonceState(prefix4=client_nonce_prefix, counter=0)

                aad = b"session-ack|server"
                nonce = send_state.next_nonce()
                ct_ack = aead_encrypt(session_key, nonce, b"OK", aad)

                send_frame(
                    conn,
                    {
                        "type": "session_ack",
                        "nonce_b64": b64e(nonce),
                        "aad_b64": b64e(aad),
                        "ciphertext_b64": b64e(ct_ack),
                    },
                )

                data_msg: Dict[str, Any] = recv_frame(conn)
                if data_msg.get("type") != "data":
                    raise ValueError(
                        f"Unexpected message type: {data_msg.get('type')}"
                    )

                nonce_in = b64d(data_msg["nonce_b64"])
                aad_in = b64d(data_msg["aad_b64"])
                ciphertext_in = b64d(data_msg["ciphertext_b64"])

                expected_nonce = recv_state.next_nonce()
                if nonce_in != expected_nonce:
                    raise ValueError(
                        "[server] Nonce mismatch (possible replay/out-of-order)."
                    )

                plaintext = aead_decrypt(
                    session_key, nonce_in, ciphertext_in, aad_in
                )
                print(
                    "[server] Decrypted message from device: "
                    f"{plaintext.decode('utf-8', errors='replace')}"
                )

                response = b"ACK: message received securely"
                aad_out = b"app-data|server->device"
                nonce_out = send_state.next_nonce()
                ct_out = aead_encrypt(
                    session_key, nonce_out, response, aad_out
                )

                send_frame(
                    conn,
                    {
                        "type": "data",
                        "nonce_b64": b64e(nonce_out),
                        "aad_b64": b64e(aad_out),
                        "ciphertext_b64": b64e(ct_out),
                    },
                )

                print("[server] Response sent. Closing connection.")


if __name__ == "__main__":
    run_server()
