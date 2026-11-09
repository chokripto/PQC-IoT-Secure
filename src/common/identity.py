"""Provisioned ML-DSA server identity key loading."""

import base64
import binascii
import os
from pathlib import Path


class IdentityConfigurationError(RuntimeError):
    """Raised when provisioned identity material is missing or malformed."""


def load_key_material(
    *,
    base64_env: str,
    file_env: str,
    default_file: str | None = None,
) -> bytes:
    """Load raw key bytes from a base64 environment value or a file."""
    encoded = os.getenv(base64_env)
    if encoded:
        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise IdentityConfigurationError(
                f"{base64_env} is not valid strict base64"
            ) from exc

    configured_path = os.getenv(file_env)
    path = configured_path or default_file
    if path:
        try:
            material = Path(path).read_bytes()
        except OSError as exc:
            raise IdentityConfigurationError(
                f"Cannot read identity material from {path!r}"
            ) from exc
        if not material:
            raise IdentityConfigurationError(
                f"Identity material in {path!r} is empty"
            )
        return material

    raise IdentityConfigurationError(
        f"Set {base64_env} or {file_env} before starting this peer"
    )


def load_server_identity_keypair() -> tuple[bytes, bytes]:
    """Load the server's provisioned ML-DSA public and secret keys."""
    public_key = load_key_material(
        base64_env="SERVER_IDENTITY_PUBLIC_KEY_B64",
        file_env="SERVER_IDENTITY_PUBLIC_KEY_FILE",
        default_file="secrets/server_identity_public.key",
    )
    secret_key = load_key_material(
        base64_env="SERVER_IDENTITY_SECRET_KEY_B64",
        file_env="SERVER_IDENTITY_SECRET_KEY_FILE",
        default_file="secrets/server_identity_secret.key",
    )
    return public_key, secret_key


def load_pinned_server_public_key() -> bytes:
    """Load the trusted server public key provisioned on the device."""
    return load_key_material(
        base64_env="PINNED_SERVER_IDENTITY_PUBLIC_KEY_B64",
        file_env="PINNED_SERVER_IDENTITY_PUBLIC_KEY_FILE",
        default_file="secrets/server_identity_public.key",
    )
