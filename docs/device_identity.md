# Device identity lifecycle

Protocol v3 authenticates each enrolled device with a distinct ML-DSA-65 key
pair. The server trusts only public keys in its locally provisioned registry.
The device private key is never transmitted.

## Enroll a device

After building the Docker image and generating the server identity:

```bash
docker run --rm -v "$PWD/secrets:/app/secrets" pqc-iot-secure \
  python -m scripts.manage_device_identity enroll \
  --device-id device-001
```

This creates:

- `secrets/device-001/device_identity_public.key`;
- `secrets/device-001/device_identity_secret.key` with mode `0600`;
- an active generation-1 record in `secrets/device_registry.json`.

Enrollment refuses to replace an existing identity.

## Rotate a compromised or expiring key

```bash
docker run --rm -v "$PWD/secrets:/app/secrets" pqc-iot-secure \
  python -m scripts.manage_device_identity rotate \
  --device-id device-001
```

Rotation generates a new key pair, increments the generation, and replaces the
registry trust anchor. The previous key is no longer accepted. Distribute the
new private key to the intended device through a trusted provisioning channel.

## Revoke a device

```bash
docker run --rm -v "$PWD/secrets:/app/secrets" pqc-iot-secure \
  python -m scripts.manage_device_identity revoke \
  --device-id device-001
```

Revocation retains the audit-relevant identifier and generation but changes the
status to `revoked`. A revoked device is rejected before ML-KEM decapsulation
and before creation of an application-data channel.

The demo server loads the registry at startup. Restart it after enrollment,
rotation, or revocation. Production systems should use an authenticated,
transactional identity service with live revocation distribution and audit
logging.

## Operational boundaries

- The registry contains public keys only; its integrity and write access must
  still be protected.
- Private keys should be provisioned into secure hardware when available.
- The CLI performs local atomic file replacements, but it is not a distributed
  transaction or fleet-management system.
- Recovery, ownership transfer, attestation, certificate chains, secure boot,
  firmware identity, and hardware extraction resistance remain out of scope.
- Device IDs are administrative labels, not secrets.
