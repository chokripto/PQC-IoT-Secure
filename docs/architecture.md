# Architecture and protocol sequence

## Components

```mermaid
flowchart TD
    D["Simulated IoT device<br/>ML-DSA identity"]
    S["Protocol v3 server<br/>Ephemeral ML-KEM"]
    R["Device registry<br/>Public identity state"]
    P["Pinned server<br/>public key"]
    C["AES-256-GCM<br/>data channel"]

    P --> D
    R --> S
    D <-->|"Mutually authenticated handshake"| S
    D --> C
    S --> C
```

The device private identity key remains with the simulated device. The server
loads only the device public key, key identifier, generation, and lifecycle
status from the registry. The device verifies a separately provisioned, pinned
server public key.

## Protocol v3 sequence

```mermaid
sequenceDiagram
    participant D as Device
    participant S as Server
    participant R as Registry

    S->>D: Signed server hello + ephemeral ML-KEM key
    D->>D: Verify pinned server identity
    D->>S: ML-KEM ciphertext + signed client auth
    S->>R: Authorize active current device key
    S->>S: Verify device signature, then decapsulate
    S->>D: Encrypted key-confirmation acknowledgement
    D->>S: AES-256-GCM application data
    S->>D: AES-256-GCM response
```

Both signatures cover canonical, length-prefixed transcript material. HKDF
binds the mutually authenticated transcript and derives independent keys and
nonce bases for each traffic direction.

## Trust boundary

This diagram describes a single-host research demonstration. It does not imply
secure provisioning, hardware-backed keys, remote attestation, distributed
revocation, or production-grade availability. See
[threat_model.md](threat_model.md) and [protocol.md](protocol.md).
