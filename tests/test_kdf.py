from src.common.hkdf import derive_traffic_secrets


def test_directional_traffic_secrets_are_stable_and_separated():
    shared_secret = b"\x01" * 32
    salt = b"\x02" * 16
    context = b"authenticated-transcript"

    first = derive_traffic_secrets(shared_secret, salt, context)
    second = derive_traffic_secrets(shared_secret, salt, context)

    assert first == second
    assert len(first.device_to_server_key) == 32
    assert len(first.server_to_device_key) == 32
    assert len(first.device_to_server_nonce_base) == 4
    assert len(first.server_to_device_nonce_base) == 4
    assert first.device_to_server_key != first.server_to_device_key
    assert (
        first.device_to_server_nonce_base
        != first.server_to_device_nonce_base
    )


def test_transcript_change_changes_all_traffic_secrets():
    shared_secret = b"\x01" * 32
    salt = b"\x02" * 16

    first = derive_traffic_secrets(shared_secret, salt, b"transcript-a")
    second = derive_traffic_secrets(shared_secret, salt, b"transcript-b")

    assert first.device_to_server_key != second.device_to_server_key
    assert first.server_to_device_key != second.server_to_device_key
    assert (
        first.device_to_server_nonce_base
        != second.device_to_server_nonce_base
    )
    assert (
        first.server_to_device_nonce_base
        != second.server_to_device_nonce_base
    )
