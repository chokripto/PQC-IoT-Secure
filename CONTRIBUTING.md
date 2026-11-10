# Contributing

Thank you for helping improve this research reference implementation.

## Development environment

Docker is the reference environment because it fixes Python, liboqs, and
liboqs-python versions.

```bash
git clone https://github.com/chokripto/PQC-IoT-Secure.git
cd PQC-IoT-Secure
docker build -t pqc-iot-secure .
docker run --rm pqc-iot-secure pytest -v
```

For documentation and lint-only work, create a Python 3.12 virtual environment
and install `requirements.lock`. Real PQC tests still require the pinned
liboqs library provided by the container.

## Required checks

Before opening a pull request:

```bash
docker run --rm pqc-iot-secure pytest -v
python -m compileall -q src scripts tests
ruff check .
```

The pull request must also pass dependency audit, container scanning, SBOM
generation, benchmark smoke validation, and the authenticated end-to-end test
in GitHub Actions.

## Pull requests

- Keep each pull request focused and explain its security impact.
- Add or update tests for behavior changes and negative cases.
- Update the threat model, protocol documentation, and changelog when relevant.
- Never commit private keys, generated identities, benchmark secrets, or local
  `secrets/` contents.
- Do not weaken validation or silently add fallback behavior.
- Mark breaking protocol or file-format changes explicitly.
- Use clear commit messages and avoid unrelated formatting churn.

## Cryptographic changes

Changes to algorithms, transcript construction, key derivation, nonce handling,
identity lifecycle, or wire formats require:

1. a written rationale and explicit security assumptions;
2. authoritative references such as NIST standards or primary research;
3. domain separation and canonical encoding review;
4. known-answer, interoperability, and negative tests where applicable;
5. downgrade, replay, key-compromise, and failure-mode analysis;
6. documentation of compatibility and migration consequences.

New cryptographic primitives should not be implemented from scratch when a
reviewed library is available. Experimental constructions must be labeled as
such and must not be presented as production-ready.

## Disclosure and conduct

Security vulnerabilities follow [SECURITY.md](SECURITY.md), not public issue
discussion. Participation should remain technical, respectful, and
evidence-based.
