"""Enroll, rotate, or revoke ML-DSA-65 device identities."""

import argparse
import base64
import json
import os
from pathlib import Path
from typing import Any

import oqs

from src.common.device_registry import (
    REGISTRY_SCHEMA_VERSION,
    parse_device_registry,
    validate_device_id,
)
from src.common.protocol import SIGNATURE_ALG, identity_key_id


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _load_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": REGISTRY_SCHEMA_VERSION, "devices": []}
    document = json.loads(path.read_text(encoding="utf-8"))
    parse_device_registry(document)
    return document


def _find_record(
    document: dict[str, Any], device_id: str
) -> dict[str, Any] | None:
    return next(
        (
            record
            for record in document["devices"]
            if record["device_id"] == device_id
        ),
        None,
    )


def _generate_keypair() -> tuple[bytes, bytes]:
    with oqs.Signature(SIGNATURE_ALG) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return public_key, secret_key


def provision(
    *,
    action: str,
    device_id: str,
    registry_path: Path,
    secrets_root: Path,
) -> dict[str, Any]:
    validate_device_id(device_id)
    document = _load_document(registry_path)
    current = _find_record(document, device_id)

    if action == "enroll" and current is not None:
        raise ValueError("Device is already enrolled; use rotate")
    if action == "rotate" and current is None:
        raise ValueError("Device is not enrolled; use enroll")

    public_key, secret_key = _generate_keypair()
    generation = 1 if current is None else current["generation"] + 1
    record = {
        "device_id": device_id,
        "status": "active",
        "generation": generation,
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "key_id_hex": identity_key_id(public_key).hex(),
    }

    device_directory = secrets_root / device_id
    _atomic_write(
        device_directory / "device_identity_public.key",
        public_key,
        0o644,
    )
    _atomic_write(
        device_directory / "device_identity_secret.key",
        secret_key,
        0o600,
    )

    if current is None:
        document["devices"].append(record)
    else:
        document["devices"][document["devices"].index(current)] = record
    parse_device_registry(document)
    rendered = (
        json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    _atomic_write(registry_path, rendered, 0o644)
    return record


def revoke(*, device_id: str, registry_path: Path) -> dict[str, Any]:
    validate_device_id(device_id)
    document = _load_document(registry_path)
    current = _find_record(document, device_id)
    if current is None:
        raise ValueError("Device is not enrolled")
    current["status"] = "revoked"
    parse_device_registry(document)
    rendered = (
        json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    _atomic_write(registry_path, rendered, 0o644)
    return current


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage the demo device identity lifecycle."
    )
    parser.add_argument("action", choices=("enroll", "rotate", "revoke"))
    parser.add_argument("--device-id", required=True)
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path("secrets/device_registry.json"),
    )
    parser.add_argument(
        "--secrets-root",
        type=Path,
        default=Path("secrets"),
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.action == "revoke":
        record = revoke(
            device_id=args.device_id,
            registry_path=args.registry,
        )
    else:
        record = provision(
            action=args.action,
            device_id=args.device_id,
            registry_path=args.registry,
            secrets_root=args.secrets_root,
        )
    print(
        f"{args.action}: device={record['device_id']} "
        f"status={record['status']} generation={record['generation']} "
        f"key_id={record['key_id_hex']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
