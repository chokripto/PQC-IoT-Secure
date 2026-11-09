# Post-Quantum Secure Communication for IoT

[![CI](https://github.com/chokripto/PQC-IoT-Secure/actions/workflows/ci.yml/badge.svg)](https://github.com/chokripto/PQC-IoT-Secure/actions/workflows/ci.yml)

## Overview

This repository is a research and educational reference implementation of an
authenticated post-quantum secure channel between a simulated IoT device and a
server.

- **ML-KEM-768** establishes a shared secret.
- **ML-DSA-65** authenticates the server using an out-of-band pinned key.
- **HKDF-SHA-256** binds traffic secrets to the authenticated transcript.
- **AES-256-GCM** protects application data.

The project is a prototype and is not a production replacement for TLS.

## Threat model

The network attacker may observe, inject, modify, delete, and replay packets.
The design targets confidentiality, integrity, server authentication,
transcript binding, replay detection, and resistance to store-now-decrypt-later
attacks.

Physical compromise, side channels, secure boot, device authentication, and
the full identity lifecycle remain outside the current scope.

See [docs/threat_model.md](docs/threat_model.md).

## Protocol v2

1. The server creates an ephemeral ML-KEM-768 key pair.
2. It signs the canonical server transcript with ML-DSA-65.
3. The device verifies the signature using its provisioned public key.
4. The device encapsulates only after successful authentication.
5. Both peers bind the full transcript to HKDF-SHA-256.
6. They derive independent AES-256-GCM keys and nonce bases for:
   - device to server;
   - server to device.
7. Per-direction 64-bit counters provide unique 96-bit nonces and fail closed
   before wraparound.

See [docs/protocol.md](docs/protocol.md).

## Run with Docker

Generate the server identity once:

```bash
mkdir -p secrets
docker build -t pqc-iot-secure .
docker run --rm -v "$PWD/secrets:/app/secrets" \
  pqc-iot-secure python -m scripts.generate_server_identity
```

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
the measurement methodology, and comparison limitations.

## Security notes

- The private ML-DSA identity key is excluded from Git and image layers.
- Docker mounts identity material read-only.
- Raw shared secrets and traffic keys are never logged.
- Protocol v2 is intentionally incompatible with v1.
- Frames are capped at 64 KiB and must be strict UTF-8 JSON objects.
- Duplicate or unknown fields, invalid Base64, and non-canonical field sizes are rejected.
- Connected peers are subject to bounded network I/O timeouts.
- Secure provisioning of the pinned public key remains an operational
  requirement.

## Repository structure

- `src/server/`: authenticated server endpoint.
- `src/device/`: simulated IoT device.
- `src/common/`: framing, transcript, HKDF, AEAD, and identity utilities.
- `scripts/`: identity provisioning utilities.
- `tests/`: interoperability and negative security tests.
- `docs/`: protocol and threat-model documentation.

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
- [ ] Device authentication and identity lifecycle management

## License

A formal license will be selected during the repository governance phase.
Until then, no permission is granted beyond rights provided by applicable law.
