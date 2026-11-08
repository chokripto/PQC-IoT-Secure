# Protocol (v1)

## Handshake
- Server generates ML-KEM-768 keypair and sends `pk`, `session_id`, `salt`, and `server_nonce_prefix`.
- Device encapsulates with ML-KEM-768 using `pk`, producing `ct` and `shared_secret`.
- Device sends `ct` and its `client_nonce_prefix`.
- Both sides derive `session_key = HKDF(shared_secret, salt, info)` where `info` binds the session_id.

## Data Channel
- AES-GCM is used as AEAD for app data.
- Nonces are 12 bytes: 4-byte prefix + 8-byte counter.
- Each direction uses a different prefix to avoid collisions.

