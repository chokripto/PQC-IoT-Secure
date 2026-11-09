import json
import stat

import pytest

from scripts import manage_device_identity
from src.common.device_registry import (
    DeviceAuthorizationError,
    authorize_device,
    parse_device_registry,
)
from src.common.protocol import identity_key_id


def test_enroll_rotate_and_revoke_lifecycle(tmp_path, monkeypatch):
    registry_path = tmp_path / "device_registry.json"
    secrets_root = tmp_path / "devices"
    first_public = b"a" * 1952
    second_public = b"b" * 1952
    keypairs = iter(
        [
            (first_public, b"first-secret"),
            (second_public, b"second-secret"),
        ]
    )
    monkeypatch.setattr(
        manage_device_identity,
        "_generate_keypair",
        lambda: next(keypairs),
    )

    enrolled = manage_device_identity.provision(
        action="enroll",
        device_id="device-001",
        registry_path=registry_path,
        secrets_root=secrets_root,
    )
    assert enrolled["generation"] == 1
    secret_path = (
        secrets_root / "device-001" / "device_identity_secret.key"
    )
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600

    rotated = manage_device_identity.provision(
        action="rotate",
        device_id="device-001",
        registry_path=registry_path,
        secrets_root=secrets_root,
    )
    assert rotated["generation"] == 2
    assert secret_path.read_bytes() == b"second-secret"

    document = json.loads(registry_path.read_text(encoding="utf-8"))
    records = parse_device_registry(document)
    with pytest.raises(DeviceAuthorizationError, match="not current"):
        authorize_device(
            records,
            "device-001",
            identity_key_id(first_public),
        )
    authorize_device(
        records,
        "device-001",
        identity_key_id(second_public),
    )

    revoked = manage_device_identity.revoke(
        device_id="device-001",
        registry_path=registry_path,
    )
    assert revoked["status"] == "revoked"
    records = parse_device_registry(
        json.loads(registry_path.read_text(encoding="utf-8"))
    )
    with pytest.raises(DeviceAuthorizationError, match="revoked"):
        authorize_device(
            records,
            "device-001",
            identity_key_id(second_public),
        )


def test_enrollment_refuses_silent_identity_replacement(
    tmp_path, monkeypatch
):
    registry_path = tmp_path / "device_registry.json"
    secrets_root = tmp_path / "devices"
    monkeypatch.setattr(
        manage_device_identity,
        "_generate_keypair",
        lambda: (b"a" * 1952, b"secret"),
    )
    manage_device_identity.provision(
        action="enroll",
        device_id="device-001",
        registry_path=registry_path,
        secrets_root=secrets_root,
    )

    with pytest.raises(ValueError, match="use rotate"):
        manage_device_identity.provision(
            action="enroll",
            device_id="device-001",
            registry_path=registry_path,
            secrets_root=secrets_root,
        )
