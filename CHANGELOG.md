# Changelog

All notable changes are documented in this file. The project follows
[Semantic Versioning](https://semver.org/), with pre-1.0 minor releases allowed
to introduce breaking protocol changes.

## [Unreleased]

### Planned

- Evidence-driven improvements identified through review, testing, and research.

## [0.3.0] - 2026-11-10

### Added

- Protocol v3 mutual ML-DSA-65 authentication for server and enrolled devices.
- Device enrollment, key rotation, revocation, and strict registry enforcement.
- Transcript-bound ML-KEM-768 key establishment and directional traffic keys.
- Strict framing, schema, Base64, size, and timeout validation.
- Reproducible cryptographic benchmark harness.
- CI tests, dependency audit, container vulnerability scanning, and SBOM.
- Security, contribution, licensing, and brand-usage policies.

### Changed

- Container build uses a pinned Python base digest, multi-stage compilation, and
  a non-root runtime user.
- Dependencies are installed from a reviewed lock file.
- Protocol v3 is intentionally incompatible with protocol v2.

### Security

- Added negative tests for modified transcripts, signatures, stale keys,
  revoked devices, invalid frames, replay, and nonce exhaustion.

### Limitations

This remains a research and educational prototype, not a production replacement
for TLS or a distributed IoT identity platform.

[Unreleased]: https://github.com/chokripto/PQC-IoT-Secure/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/chokripto/PQC-IoT-Secure/releases/tag/v0.3.0
