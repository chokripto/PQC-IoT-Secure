"""Protocol constants shared by the device and server."""

KEM_ALG = "ML-KEM-768"
PROTOCOL_LABEL = b"pqc-iot-demo-v1"


def build_info(session_id: bytes) -> bytes:
    """Build the HKDF context for protocol version 1."""
    return PROTOCOL_LABEL + b"|" + session_id
