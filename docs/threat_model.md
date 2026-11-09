# Threat Model

## Attacker capabilities

- Passive eavesdropping on the network
- Active modification, injection, deletion, and replay of packets
- Server or device impersonation attempts
- Use of an unknown, stale, or revoked device identity
- “Store now, decrypt later” strategy

## Security goals

- Confidentiality of IoT telemetry
- Integrity and authenticity of application messages
- Mutual authentication of provisioned server and device identities
- Proof of possession of the enrolled device private key
- Binding of both identities and all negotiated parameters to session keys
- Rejection of unknown, stale-key, and revoked devices
- Replay resistance at the session level
- Quantum-resistant key establishment and peer authentication

## Trust assumptions

- Server and device public keys are provisioned through trusted channels.
- The server registry is protected from unauthorized modification.
- Both peers protect their ML-DSA private keys.
- Administrators restart the demo server after registry changes.
- Randomness provided by the operating system is trustworthy.
- Endpoint software and host operating systems are not compromised.

## Out of scope

- Physical compromise and hardware key extraction
- Side-channel and fault-injection resistance
- Secure boot, firmware update, and rollback protection
- Remote attestation and hardware-backed device identity
- Certificate-chain validation and automated ownership transfer
- Distributed, real-time fleet revocation and recovery
- Availability against volumetric denial-of-service attacks
