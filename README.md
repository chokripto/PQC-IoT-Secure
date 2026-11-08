# Post-Quantum Secure Communication for IoT (ML-KEM-768 + AES-GCM)

## Overview
This repository demonstrates a practical **post-quantum secure channel** between a simulated IoT device and a server.
The design is **hybrid**:
- Post-quantum cryptography (PQC) is used for **key establishment** (ML-KEM-768).
- Symmetric cryptography is used for **data protection** (AES-GCM AEAD).

The goal is an industry-oriented, deployable architecture that is **quantum-resistant** for long-lived IoT deployments.

---

## Threat Model (High Level)
We assume:
- An attacker can eavesdrop, replay, and tamper with traffic (Dolev–Yao style network control).
- Devices are resource-constrained and may operate for years.
- We aim to mitigate:
  - Passive interception (confidentiality)
  - Active tampering (integrity/authenticity)
  - Replay attacks (nonces / session rules)
  - “Store now, decrypt later” risk (PQC handshake)

Out of scope (first iteration):
- Physical compromise of the device
- Side-channel resistance (timing/power)
- PKI / certificate lifecycle (can be added later)

See: `docs/threat_model.md`.

---

## Protocol Design
### Handshake (Key Establishment)
1. Server generates ML-KEM keys:
   - $(pk, sk) \\leftarrow \\text{ML-KEM.KeyGen}()$
2. Server sends `pk` to device.
3. Device encapsulates:
   - $(ct, ss) \\leftarrow \\text{ML-KEM.Encap}(pk)$
4. Device sends `ct` to server.
5. Server decapsulates:
   - $ss \\leftarrow \\text{ML-KEM.Decap}(sk, ct)$
6. Before encapsulation, the device verifies an **ML-DSA-65 signature** over the
   canonical server transcript using a public identity key provisioned out of band.
7. Both derive a session key bound to the full handshake transcript:
   - $K \\leftarrow \\text{HKDF}(ss, \\text{salt}, \\text{transcript-hash})$

### Secure Data Channel
Application messages use AEAD:
- $\\text{ciphertext} \\leftarrow \\text{AES-GCM.Enc}(K, nonce, plaintext, aad)$

`nonce` uniqueness is enforced per session.

See: `docs/protocol.md`.

---

## Tech Stack
- Python (reference implementation)
- PQC library (ML-KEM-768)
- AES-GCM (AEAD)
- HKDF (key derivation)
- Simple client/server transport (TCP) for demonstration

---

## Repository Structure
- `src/server/server_app.py` : server endpoint, Kyber keygen, session handling
- `src/device/device_client.py`: device simulation, Kyber encapsulation, encrypted messaging
- `src/common/*` : crypto utilities (HKDF, AEAD helpers, message framing)
- `docs/` : threat model and protocol documentation
- `tests/` : small unit tests for KDF/AEAD

---

## How to Run (Planned)
1. Install dependencies:
   - `pip install -r requirements.txt`
2. Generate the server identity once:
   - `python -m scripts.generate_server_identity`
   - The private key is created with mode `0600` and must never be committed.
3. Start server:
   - `python -m src.server.server_app`
4. Start device client:
   - `python -m src.device.device_client`
5. Observe:
   - ML-KEM handshake
   - Derived session key (printed as hash / truncated)
   - AES-GCM encrypted messages

---

## Security Notes
- The server handshake is authenticated with ML-DSA-65.
- The device trusts only the provisioned server identity public key.
- Identity keys are mounted read-only and excluded from Git and Docker image layers.
- Session key material is never logged directly (only hashes/truncations for demo).
- Nonce reuse is prevented (per-session counter).
- This is a demo; production hardening requires:
  - secure key storage
  - authenticated distribution of server public key (PKI / pinning)
  - robust error handling and rate limiting

---

## Roadmap
- [x] Implement ML-KEM-768 handshake
- [ ] Implement HKDF key derivation
- [ ] Implement AES-GCM secure channel
- [ ] Add replay protection and session IDs
- [ ] Add unit tests and negative tests
- [x] Authenticate the server with a pinned ML-DSA-65 identity key
- [ ] Add device authentication and identity lifecycle management
- [ ] Add metrics: latency + message overhead

---

## License
CHOKRI
