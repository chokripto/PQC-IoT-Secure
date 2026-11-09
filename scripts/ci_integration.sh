#!/usr/bin/env bash
set -euo pipefail

image="${1:-pqc-iot-secure:ci}"
network="pqc-iot-ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
server_container="pqc-iot-server-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
secrets_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pqc-iot-secrets-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"

cleanup() {
  docker rm -f "$server_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ -d "$secrets_dir" ]]; then
    docker run --rm \
      --volume "$secrets_dir:/cleanup" \
      "$image" \
      sh -c 'find /cleanup -mindepth 1 -delete' \
      >/dev/null 2>&1 || true
    rm -rf "$secrets_dir"
  fi
}
trap cleanup EXIT

mkdir -p "$secrets_dir"
docker network create "$network" >/dev/null

docker run --rm \
  --volume "$secrets_dir:/app/secrets" \
  "$image" \
  python -m scripts.generate_server_identity

docker run --rm \
  --volume "$secrets_dir:/app/secrets" \
  "$image" \
  python -m scripts.manage_device_identity enroll \
    --device-id device-001

docker run --detach \
  --name "$server_container" \
  --network "$network" \
  --network-alias server \
  --env SERVER_IDENTITY_PUBLIC_KEY_FILE=/run/secrets/server_identity_public.key \
  --env SERVER_IDENTITY_SECRET_KEY_FILE=/run/secrets/server_identity_secret.key \
  --env DEVICE_REGISTRY_FILE=/run/secrets/device_registry.json \
  --volume "$secrets_dir:/run/secrets:ro" \
  "$image" >/dev/null

for _ in $(seq 1 30); do
  if docker logs "$server_container" 2>&1 | grep -q "Listening on"; then
    break
  fi
  if ! docker inspect -f '{{.State.Running}}' "$server_container" 2>/dev/null | grep -q true; then
    docker logs "$server_container"
    exit 1
  fi
  sleep 1
done

if ! docker logs "$server_container" 2>&1 | grep -q "Listening on"; then
  echo "Server did not become ready within 30 seconds" >&2
  docker logs "$server_container"
  exit 1
fi

docker run --rm \
  --network "$network" \
  --env PINNED_SERVER_IDENTITY_PUBLIC_KEY_FILE=/run/secrets/server_identity_public.key \
  --env DEVICE_ID=device-001 \
  --env DEVICE_IDENTITY_PUBLIC_KEY_FILE=/run/secrets/device-001/device_identity_public.key \
  --env DEVICE_IDENTITY_SECRET_KEY_FILE=/run/secrets/device-001/device_identity_secret.key \
  --volume "$secrets_dir:/run/secrets:ro" \
  "$image" \
  python -m src.device.device_client

server_status="$(docker wait "$server_container")"
docker logs "$server_container"

if [[ "$server_status" != "0" ]]; then
  echo "Server exited with status $server_status" >&2
  exit "$server_status"
fi
