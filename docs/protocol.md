# Protocol (v3)

## Trust anchors

The server owns a long-term ML-DSA-65 identity key pair. Its public key is
provisioned on each device through a trusted out-of-band process.

Each device owns a distinct ML-DSA-65 identity key pair. Its private key remains
on the device. The server stores the corresponding public key, key identifier,
generation, and lifecycle status in a protected registry.

## Mutually authenticated handshake

1. The server generates an ephemeral ML-KEM-768 key pair.
2. The server signs a canonical, length-prefixed transcript containing the
   protocol version, algorithm identifiers, server identity key identifier,
   ephemeral ML-KEM key, session ID, and HKDF salt.
3. The device verifies the server key identifier and ML-DSA-65 signature
   against its pinned server public key.
4. Only after server authentication, the device encapsulates to ML-KEM-768.
5. The device builds a canonical client-auth transcript containing:
   - protocol version and algorithm identifiers;
   - device ID and current device key identifier;
   - ML-KEM ciphertext;
   - SHA-256 hash of the complete server transcript.
6. The device signs that transcript with its provisioned ML-DSA-65 key.
7. The server validates the exact message schema, looks up the device, requires
   an `active` status and current key identifier, then verifies the signature.
8. Only after device authentication, the server decapsulates ML-KEM.
9. Both peers hash both canonical transcript contributions and bind the result
   to HKDF-SHA-256.
10. HKDF derives independent AES-256-GCM keys and nonce bases for both traffic
    directions.
11. The encrypted session acknowledgement provides key confirmation.

A change to either identity, any algorithm identifier, the ML-KEM key or
ciphertext, session ID, salt, or device ID invalidates a signature or changes
all transcript-bound traffic secrets.

## Data channel

- AES-256-GCM protects application data.
- Each direction has an independent key and 32-bit nonce base.
- A nonce is the derived base followed by a 64-bit counter.
- Counters increment before use and fail closed before wraparound.
- A key from one direction cannot authenticate ciphertext from the other.

## Lifecycle enforcement

The server accepts only an enrolled, active device generation. Rotation replaces
the trusted public key and increments the generation. Revocation changes the
record status and blocks new sessions. The demo loads its registry at startup,
so lifecycle changes require a server restart.

See [device_identity.md](device_identity.md).

## Version boundary

Protocol v3 is intentionally incompatible with v2. Version 2 authenticated only
the server and used an unsigned `client_kem` contribution. Version 3 replaces
it with a signed `client_auth` contribution bound to the server transcript.

## Limitations

This is a research prototype, not a replacement for TLS or a fleet identity
platform. It does not provide certificate chains, remote attestation, secure
boot, hardware-backed key isolation, distributed revocation, or recovery.
