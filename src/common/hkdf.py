"""HKDF-based directional traffic-secret derivation."""

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class TrafficSecrets:
    """Independent keys and nonce bases for both traffic directions."""

    device_to_server_key: bytes
    server_to_device_key: bytes
    device_to_server_nonce_base: bytes
    server_to_device_nonce_base: bytes


def _derive(
    shared_secret: bytes,
    salt: bytes,
    context: bytes,
    label: bytes,
    length: int,
) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=b"pqc-iot/traffic-secret/v2|" + label + b"|" + context,
    ).derive(shared_secret)


def derive_traffic_secrets(
    shared_secret: bytes,
    salt: bytes,
    context: bytes,
) -> TrafficSecrets:
    """Derive role-separated AES-256 keys and 32-bit nonce bases."""

    return TrafficSecrets(
        device_to_server_key=_derive(
            shared_secret, salt, context, b"device-to-server/key", 32
        ),
        server_to_device_key=_derive(
            shared_secret, salt, context, b"server-to-device/key", 32
        ),
        device_to_server_nonce_base=_derive(
            shared_secret, salt, context, b"device-to-server/nonce", 4
        ),
        server_to_device_nonce_base=_derive(
            shared_secret, salt, context, b"server-to-device/nonce", 4
        ),
    )
