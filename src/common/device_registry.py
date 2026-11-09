"""Strict server-side registry for provisioned device identities."""

import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.common.crypto_utils import b64d
from src.common.protocol import identity_key_id

REGISTRY_SCHEMA_VERSION = 1
DEVICE_PUBLIC_KEY_BYTES = 1952
_DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ALLOWED_STATUSES = {"active", "revoked"}


class DeviceAuthorizationError(RuntimeError):
    """Raised when a device identity is unknown, revoked, or inconsistent."""


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    status: str
    generation: int
    public_key: bytes
    key_id: bytes


def validate_device_id(device_id: str) -> str:
    if not isinstance(device_id, str) or not _DEVICE_ID_PATTERN.fullmatch(
        device_id
    ):
        raise ValueError(
            "device_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"
        )
    return device_id


def _parse_record(value: Any) -> DeviceRecord:
    if not isinstance(value, dict):
        raise ValueError("Each registry device must be an object")
    expected = {
        "device_id",
        "status",
        "generation",
        "public_key_b64",
        "key_id_hex",
    }
    if set(value) != expected:
        raise ValueError("Device registry record has an invalid schema")

    device_id = validate_device_id(value["device_id"])
    status = value["status"]
    generation = value["generation"]
    if status not in _ALLOWED_STATUSES:
        raise ValueError("Device status must be active or revoked")
    if type(generation) is not int or generation < 1:
        raise ValueError("Device generation must be a positive integer")

    public_key = b64d(value["public_key_b64"])
    if len(public_key) != DEVICE_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Device public key must be {DEVICE_PUBLIC_KEY_BYTES} bytes"
        )
    try:
        configured_key_id = bytes.fromhex(value["key_id_hex"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Device key ID must be hexadecimal") from exc
    computed_key_id = identity_key_id(public_key)
    if not hmac.compare_digest(configured_key_id, computed_key_id):
        raise ValueError("Device key ID does not match its public key")

    return DeviceRecord(
        device_id=device_id,
        status=status,
        generation=generation,
        public_key=public_key,
        key_id=computed_key_id,
    )


def parse_device_registry(document: Any) -> dict[str, DeviceRecord]:
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "devices",
    }:
        raise ValueError("Device registry has an invalid top-level schema")
    if document["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise ValueError("Unsupported device registry schema version")
    if not isinstance(document["devices"], list):
        raise ValueError("Device registry devices must be a list")

    records: dict[str, DeviceRecord] = {}
    for raw_record in document["devices"]:
        record = _parse_record(raw_record)
        if record.device_id in records:
            raise ValueError(f"Duplicate device ID: {record.device_id}")
        records[record.device_id] = record
    return records


def load_device_registry() -> dict[str, DeviceRecord]:
    path = Path(
        os.getenv("DEVICE_REGISTRY_FILE", "secrets/device_registry.json")
    )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeviceAuthorizationError(
            f"Cannot load device registry from {str(path)!r}"
        ) from exc
    try:
        return parse_device_registry(document)
    except (TypeError, ValueError) as exc:
        raise DeviceAuthorizationError("Device registry is invalid") from exc


def authorize_device(
    records: dict[str, DeviceRecord],
    device_id: str,
    presented_key_id: bytes,
) -> DeviceRecord:
    record = records.get(device_id)
    if record is None:
        raise DeviceAuthorizationError("Device is not enrolled")
    if record.status != "active":
        raise DeviceAuthorizationError("Device identity is revoked")
    if not hmac.compare_digest(record.key_id, presented_key_id):
        raise DeviceAuthorizationError("Device key ID is not current")
    return record
