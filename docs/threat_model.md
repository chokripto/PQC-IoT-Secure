# Threat Model

## Attacker capabilities

- Passive eavesdropping on the network
- Active modification, injection, deletion, and replay of packets
- Server impersonation attempts
- “Store now, decrypt later” strategy

## Security goals

- Confidentiality of IoT telemetry
- Integrity and authenticity of application messages
- Authentication of the provisioned server identity
- Cryptographic binding of negotiated parameters to the session key
- Replay resistance at the session level
- Quantum-resistant key establishment and server authentication

## Trust assumptions

- The device receives the correct ML-DSA-65 public key through a trusted
  provisioning process.
- The server protects its ML-DSA private key from disclosure and unauthorized
  use.
- Randomness provided by the operating system is trustworthy.
- The endpoint software and host operating systems are not already compromised.

## Out of scope (v1)

- Device identity authentication
- Identity key rotation and revocation
- Physical compromise and hardware extraction
- Side-channel and fault-injection resistance
- Secure boot, firmware update, and rollback protection
