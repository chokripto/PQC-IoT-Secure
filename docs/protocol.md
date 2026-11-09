# Protocol (v2)

## Trust anchor

The server owns a long-term ML-DSA-65 identity key pair. The private key is
available only to the server. The corresponding public key is provisioned on
the device through a trusted out-of-band process before the first connection.
A public key received only through the network is never trusted.

## Authenticated handshake

1. The server generates an ephemeral ML-KEM-768 key pair.
2. The server creates a canonical, length-prefixed transcript containing:
   - protocol version;
   - KEM and signature algorithm identifiers;
   - identity key identifier;
   - ephemeral ML-KEM public key;
   - session ID and HKDF salt.
3. The server signs that transcript with ML-DSA-65.
4. The device verifies that the advertised key identifier matches its pinned
   public key and verifies the ML-DSA signature.
5. Only after successful authentication, the device encapsulates to the
   verified ML-KEM public key.
6. The device sends the ML-KEM ciphertext.
7. Both peers hash the server and client transcript contributions.
8. Both peers use HKDF-SHA-256 with distinct labels to derive:
   - the AES-256-GCM key for device-to-server traffic;
   - the AES-256-GCM key for server-to-device traffic;
   - the 32-bit nonce base for device-to-server traffic;
   - the 32-bit nonce base for server-to-device traffic.

A modified server parameter, ML-KEM key, ciphertext, algorithm identifier,
session identifier, or salt invalidates the server signature or changes all
transcript-bound traffic secrets.

## Data channel

- AES-256-GCM is used as AEAD for application data.
- Each direction has an independent key and nonce base.
- A nonce is 96 bits: a derived 32-bit base followed by a 64-bit counter.
- Counters start at zero, increment before first use, and never wrap.
- Counter exhaustion closes the cryptographic context instead of reusing a
  nonce.
- A key from one direction cannot authenticate ciphertext from the opposite
  direction.
- The encrypted session acknowledgement provides key confirmation.

## Version boundary

Protocol v2 is intentionally incompatible with v1. Version 1 transmitted
random nonce prefixes and used one AES-GCM key for both directions. Version 2
derives role-separated keys and nonce bases from the authenticated handshake.

## Current identity boundary

Version 2 authenticates the server to the device. Device authentication,
identity rotation, revocation, and recovery are separate lifecycle controls
that remain to be implemented.
