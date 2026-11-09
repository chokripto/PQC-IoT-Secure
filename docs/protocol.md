# Protocol (v1)

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
   - session ID and HKDF salt;
   - server nonce prefix.
3. The server signs that transcript with ML-DSA-65.
4. The device verifies that the advertised key identifier matches its pinned
   public key and verifies the ML-DSA signature.
5. Only after successful authentication, the device encapsulates to the
   verified ML-KEM public key.
6. The device sends the ciphertext and its nonce prefix.
7. Both peers hash the server and client transcript contributions and derive
   the session key with HKDF.

A modified server parameter, ML-KEM key, ciphertext, algorithm identifier,
session identifier, salt, or nonce prefix changes the transcript-bound key or
invalidates the server signature.

## Data channel

- AES-GCM is used as AEAD for application data.
- Nonces are 12 bytes: 4-byte prefix plus 8-byte counter.
- Each direction currently uses a different prefix.
- The encrypted session acknowledgement provides key confirmation.

## Current identity boundary

Version 1 authenticates the server to the device. Device authentication,
identity rotation, revocation, and recovery are separate lifecycle controls
that remain to be implemented.
