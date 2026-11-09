import json
import socket
import struct
from typing import Any

MAX_FRAME_SIZE = 64 * 1024


class ProtocolError(ValueError):
    """Raised when a peer sends a malformed protocol frame."""


def send_frame(sock: socket.socket, obj: dict[str, Any]) -> None:
    if not isinstance(obj, dict):
        raise TypeError("Protocol frames must be JSON objects")

    data = json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if not 0 < len(data) <= MAX_FRAME_SIZE:
        raise ProtocolError(f"Frame size is outside 1..{MAX_FRAME_SIZE} bytes")

    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except TimeoutError as exc:
            raise ProtocolError("Timed out while receiving a frame") from exc
        if not chunk:
            raise ConnectionError("Socket closed while receiving data.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def recv_frame(sock: socket.socket) -> dict[str, Any]:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if not 0 < length <= MAX_FRAME_SIZE:
        raise ProtocolError(f"Invalid frame length: {length}")

    payload = _recv_exact(sock, length)
    try:
        message = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProtocolError(f"Invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Frame is not valid UTF-8 JSON") from exc

    if not isinstance(message, dict):
        raise ProtocolError("Protocol frame must contain a JSON object")
    return message
