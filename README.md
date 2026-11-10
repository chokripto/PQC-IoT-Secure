# Post-Quantum Secure Communication for IoT

[![CI](https://github.com/chokripto/PQC-IoT-Secure/actions/workflows/ci.yml/badge.svg)](https://github.com/chokripto/PQC-IoT-Secure/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.3.0-informational.svg)](CHANGELOG.md)

## Overview

This repository is a research and educational reference implementation of a
mutually authenticated post-quantum secure channel between a simulated IoT
device and a server.

- **ML-KEM-768** establishes a shared secret.
- **ML-DSA-65** mutually authenticates the server and an enrolled device.
- A strict device registry enforces active, rotated, and revoked identities.
- **HKDF-SHA-256** binds traffic secrets to the authenticated transcript.
- **AES-256-GCM** protects application data.

The project is a prototype and is not a production replacement for TLS.

## Threat model

The network attacker may observe, inject, modify, delete, and replay packets.
The design targets confidentiality, integrity, mutual peer authentication,
transcript binding, replay detection, and resistance to store-now-decrypt-later
attacks.

Physical compromise, side channels, secure boot, remote attestation, and
distributed fleet identity operations remain outside the current scope.

See [docs/threat_model.md](docs/threat_model.md).

## Protocol v3

1. The server signs its ephemeral ML-KEM-768 parameters with ML-DSA-65.
2. The device verifies the pinned server identity before encapsulation.
3. The device signs its ID, current key identifier, ML-KEM ciphertext, and the
   server-transcript hash with its own ML-DSA-65 identity.
4. The server requires an enrolled, active, current device key and verifies
   proof of possession before ML-KEM decapsulation.
5. Both peers bind the mutually authenticated transcript to HKDF-SHA-256.
6. Independent AES-256-GCM keys and nonce bases protect both directions.

See [docs/protocol.md](docs/protocol.md) and the
[architecture and sequence diagrams](docs/architecture.md).

## Run with Docker

Generate the server identity and enroll the demo device once:

```bash
mkdir -p secrets
docker build -t pqc-iot-secure .
docker run --rm -v "$PWD/secrets:/app/secrets" \
  pqc-iot-secure python -m scripts.generate_server_identity
docker run --rm -v "$PWD/secrets:/app/secrets" \
  pqc-iot-secure python -m scripts.manage_device_identity enroll \
  --device-id device-001
```

See [docs/device_identity.md](docs/device_identity.md) for rotation and
revocation commands. Restart the demo server after registry changes.

Start the server:

```bash
docker compose up --build server
```

In a second terminal, run the simulated device:

```bash
docker compose run --rm --no-deps device
```

Run the test suite:

```bash
docker run --rm pqc-iot-secure pytest -v
```

Run the reproducible cryptographic benchmark:

```bash
mkdir -p results
docker run --rm -v "$PWD/results:/results" pqc-iot-secure \
  python -m scripts.benchmark_iot \
  --iterations 100 --warmup 10 \
  --output /results/benchmark.json
```

See [docs/benchmarks.md](docs/benchmarks.md) for PowerShell instructions,
the measurement methodology, CI benchmark evidence, and comparison limitations.

## Security notes

- The private ML-DSA identity key is excluded from Git and image layers.
- Docker mounts identity material read-only.
- Raw shared secrets and traffic keys are never logged.
- Protocol v3 is intentionally incompatible with v2.
- The server rejects unknown, revoked, and stale-generation device keys.
- Frames are capped at 64 KiB and must be strict UTF-8 JSON objects.
- Duplicate or unknown fields, invalid Base64, and non-canonical field sizes are rejected.
- Connected peers are subject to bounded network I/O timeouts.
- Secure provisioning of the pinned public key remains an operational
  requirement.

## Supply-chain evidence

Every CI run builds the pinned multi-stage image, verifies the non-root runtime,
audits the locked Python dependencies, scans the image with Trivy, generates an
SPDX JSON SBOM, uploads benchmark evidence, and runs the mutually authenticated
end-to-end exchange. CI artifacts are retained for a limited period and are
supporting evidence, not a claim of production assurance.

## Repository structure

- `src/server/`: authenticated server endpoint.
- `src/device/`: simulated IoT device.
- `src/common/`: framing, transcript, HKDF, AEAD, and identity utilities.
- `scripts/`: identity provisioning utilities.
- `tests/`: interoperability and negative security tests.
- `docs/`: architecture, protocol, benchmark, identity, and threat-model documentation.

## Roadmap

- [x] ML-KEM-768 key establishment
- [x] ML-DSA-65 server authentication
- [x] Authenticated transcript binding
- [x] Directional traffic keys and nonce bases
- [x] AES-256-GCM encrypted data channel
- [x] Negative cryptographic tests
- [x] Automated CI and dependency scanning
- [x] Input and network hardening
- [x] Reproducible IoT benchmarks
- [x] Device authentication and identity lifecycle management

## Release status

The current research release is `v0.3.0`. The project follows Semantic
Versioning; pre-1.0 minor versions may introduce breaking protocol changes. See
[CHANGELOG.md](CHANGELOG.md).

## License and brand

Source code, configuration, tests, and documentation are licensed under
[Apache License 2.0](LICENSE). The license does not grant permission to use the
name, logo, signature, portrait, or visual identity of Dr. Chokri NOUAR as a
trademark or endorsement. See [BRAND_USAGE.md](BRAND_USAGE.md).

Security reports follow [SECURITY.md](SECURITY.md), and contributions follow
[CONTRIBUTING.md](CONTRIBUTING.md).
