"""Generate the server ML-DSA-65 identity used by the demo."""

import argparse
import os
from pathlib import Path

import oqs

from src.common.protocol import SIGNATURE_ALG, identity_key_id


def _write_new(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        default="secrets",
        help="directory for the raw public and private identity keys",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_dir.chmod(0o700)

    public_path = output_dir / "server_identity_public.key"
    secret_path = output_dir / "server_identity_secret.key"

    with oqs.Signature(SIGNATURE_ALG) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    _write_new(public_path, public_key, 0o644)
    _write_new(secret_path, secret_key, 0o600)

    print(f"Generated {SIGNATURE_ALG} server identity.")
    print(f"Public key: {public_path}")
    print(f"Private key: {secret_path} (mode 0600)")
    print(f"Key ID: {identity_key_id(public_key).hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
