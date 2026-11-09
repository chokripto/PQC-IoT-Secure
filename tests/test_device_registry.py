import base64
import copy
import os

import oqs
import pytest

from src.common.device_registry import (
    DeviceAuthorizationError,
    authorize_device,
    parse_device_registry,
    verify_device_signature,
)
from src.common.protocol import SIGNATURE_ALG, identity_key_id


def _document(public_key: bytes, status: str = "active"):
    return {
        "schema_version": 1,
        "devices": [
            {
                "device_id": "device-001",
                "status": status,
                "generation": 1,
                "public_key_b64": base64.b64encode(public_key).decode(
                    "ascii"
                ),
                "key_id_hex": identity_key_id(public_key).hex(),
            }
        ],
    }


def test_active_enrolled_device_is_authorized():
    public_key = os.urandom(1952)
    records = parse_device_registry(_document(public_key))

    record = authorize_device(
        records,
        "device-001",
        identity_key_id(public_key),
    )

    assert record.status == "active"
    assert record.generation == 1
    assert record.public_key == public_key


@pytest.mark.parametrize(
    ("device_id", "key_id", "message"),
    [
        ("unknown", b"x" * 32, "not enrolled"),
        ("device-001", b"x" * 32, "not current"),
    ],
)
def test_unknown_or_stale_device_identity_is_rejected(
    device_id, key_id, message
):
    public_key = os.urandom(1952)
    records = parse_device_registry(_document(public_key))

    with pytest.raises(DeviceAuthorizationError, match=message):
        authorize_device(records, device_id, key_id)


def test_revoked_device_is_rejected():
    public_key = os.urandom(1952)
    records = parse_device_registry(_document(public_key, "revoked"))

    with pytest.raises(DeviceAuthorizationError, match="revoked"):
        authorize_device(
            records,
            "device-001",
            identity_key_id(public_key),
        )


def test_registry_rejects_tampered_key_identifier():
    public_key = os.urandom(1952)
    document = _document(public_key)
    tampered = copy.deepcopy(document)
    tampered["devices"][0]["key_id_hex"] = (b"x" * 32).hex()

    with pytest.raises(ValueError, match="does not match"):
        parse_device_registry(tampered)


def test_device_signature_proves_possession_and_rejects_wrong_key():
    transcript = b"protocol-v3-client-auth-transcript"
    with oqs.Signature(SIGNATURE_ALG) as enrolled:
        public_key = enrolled.generate_keypair()
        signature = enrolled.sign(transcript)

    records = parse_device_registry(_document(public_key))
    record = records["device-001"]
    verify_device_signature(record, transcript, signature)

    with oqs.Signature(SIGNATURE_ALG) as attacker:
        attacker.generate_keypair()
        attacker_signature = attacker.sign(transcript)

    with pytest.raises(DeviceAuthorizationError, match="Invalid"):
        verify_device_signature(record, transcript, attacker_signature)
