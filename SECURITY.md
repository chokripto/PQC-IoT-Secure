# Security policy

## Supported versions

This repository is a research and educational prototype. Security fixes are
provided only for the latest release and the current `main` branch.

| Version | Supported |
| --- | --- |
| 0.3.x | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability.

Use GitHub's **Report a vulnerability** private reporting form in the
repository Security tab when it is available. If private reporting is not
available, contact the maintainer through the professional contact channel
listed on the GitHub profile and request a private reporting channel. Do not
include exploit details or secrets in the initial public message.

A useful report includes:

- affected commit or version;
- reproducible steps and expected impact;
- relevant logs with secrets removed;
- a minimal proof of concept, if safe;
- suggested mitigation, when known.

The maintainer will acknowledge a complete report when practical, assess
severity and scope, coordinate a fix, and credit the reporter if requested and
appropriate.

## Scope

In scope are protocol implementation errors, authentication or authorization
bypasses, unsafe cryptographic use, secret disclosure, replay or nonce failures,
parser and framing flaws, dependency risks, and container escape or privilege
issues caused by this repository.

The following are outside the security guarantees of this prototype:

- physical device compromise and side channels;
- secure boot, remote attestation, and firmware update security;
- hardware-backed key storage;
- distributed fleet identity operations;
- production availability and denial-of-service resilience.

## Research-prototype boundary

This project is not a production replacement for TLS and has not undergone an
independent security audit. Do not protect production systems, personal data,
or safety-critical workloads with it. Findings should be interpreted within
the documented threat model.
