"""Reproducible microbenchmarks for the PQC IoT protocol primitives."""

import argparse
import gc
import json
import math
import os
import platform
import resource
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import oqs

from src.common.crypto_utils import aead_decrypt, aead_encrypt
from src.common.hkdf import derive_traffic_secrets
from src.common.protocol import (
    KEM_ALG,
    SIGNATURE_ALG,
    build_client_auth_transcript,
    build_info,
    build_server_hello_transcript,
    handshake_transcript_hash,
    identity_key_id,
)

SCHEMA_VERSION = 1
DEFAULT_ITERATIONS = 100
DEFAULT_WARMUP = 10
MAX_ITERATIONS = 10_000
PAYLOAD = b"temperature=23.7C; humidity=41%"
AAD = b"app-data|device->server"
SESSION_ID = b"benchmark-run-01"
SALT = b"benchmark-salt!!"
CONTEXT = b"pqc-iot-benchmark-context-v1"


def _percentile_nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def summarize_ns(values: list[int]) -> dict[str, int]:
    """Summarize integer nanosecond observations without interpolation."""
    if not values:
        raise ValueError("At least one timing observation is required")
    return {
        "samples": len(values),
        "min_ns": min(values),
        "median_ns": round(statistics.median(values)),
        "mean_ns": round(statistics.fmean(values)),
        "p95_ns": _percentile_nearest_rank(values, 0.95),
        "max_ns": max(values),
    }


def measure(
    operation: Callable[[], object],
    iterations: int,
    warmup: int,
) -> dict[str, int]:
    """Warm up, then time one operation per sample with perf_counter_ns."""
    for _ in range(warmup):
        operation()

    observations: list[int] = []
    gc_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(iterations):
            start = time.perf_counter_ns()
            operation()
            observations.append(time.perf_counter_ns() - start)
    finally:
        if gc_enabled:
            gc.enable()
    return summarize_ns(observations)


def _peak_rss_kib() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return round(peak / 1024)
    return round(peak)


def _environment() -> dict[str, Any]:
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        affinity = len(os.sched_getaffinity(0))
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "liboqs_version": oqs.oqs_version(),
        "liboqs_python_version": getattr(
            oqs, "oqs_python_version", lambda: "unknown"
        )(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "logical_cpus_visible": os.cpu_count(),
        "cpu_affinity_count": affinity,
        "timer": "time.perf_counter_ns",
        "timer_resolution_ns": round(
            time.get_clock_info("perf_counter").resolution * 1_000_000_000
        ),
    }


def run_benchmarks(iterations: int, warmup: int) -> dict[str, Any]:
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError(f"iterations must be in 1..{MAX_ITERATIONS}")
    if not 0 <= warmup <= MAX_ITERATIONS:
        raise ValueError(f"warmup must be in 0..{MAX_ITERATIONS}")

    with oqs.KeyEncapsulation(KEM_ALG) as server_kem:
        kem_public_key = server_kem.generate_keypair()
        with oqs.KeyEncapsulation(KEM_ALG) as client_kem:
            kem_ciphertext, shared_secret = client_kem.encap_secret(
                kem_public_key
            )

            with oqs.Signature(SIGNATURE_ALG) as signer:
                identity_public_key = signer.generate_keypair()
                transcript = build_server_hello_transcript(
                    kem_public_key,
                    SESSION_ID,
                    SALT,
                    identity_key_id(identity_public_key),
                )
                signature = signer.sign(transcript)

                with (
                    oqs.Signature(SIGNATURE_ALG) as verifier,
                    oqs.Signature(SIGNATURE_ALG) as device_signer,
                ):
                    device_public_key = device_signer.generate_keypair()
                    device_key_id = identity_key_id(device_public_key)
                    if not verifier.verify(
                        transcript, signature, identity_public_key
                    ):
                        raise RuntimeError("ML-DSA benchmark setup failed")

                    with (
                        oqs.KeyEncapsulation(KEM_ALG) as kem_keygen,
                        oqs.Signature(SIGNATURE_ALG) as sig_keygen,
                    ):
                        timings = {
                            "ml_kem_768_keygen": measure(
                                kem_keygen.generate_keypair,
                                iterations,
                                warmup,
                            ),
                            "ml_kem_768_encapsulate": measure(
                                lambda: client_kem.encap_secret(
                                    kem_public_key
                                ),
                                iterations,
                                warmup,
                            ),
                            "ml_kem_768_decapsulate": measure(
                                lambda: server_kem.decap_secret(
                                    kem_ciphertext
                                ),
                                iterations,
                                warmup,
                            ),
                            "ml_dsa_65_keygen": measure(
                                sig_keygen.generate_keypair,
                                iterations,
                                warmup,
                            ),
                            "ml_dsa_65_sign": measure(
                                lambda: signer.sign(transcript),
                                iterations,
                                warmup,
                            ),
                            "ml_dsa_65_verify": measure(
                                lambda: verifier.verify(
                                    transcript,
                                    signature,
                                    identity_public_key,
                                ),
                                iterations,
                                warmup,
                            ),
                            "hkdf_sha256_traffic_secrets": measure(
                                lambda: derive_traffic_secrets(
                                    shared_secret,
                                    SALT,
                                    CONTEXT,
                                ),
                                iterations,
                                warmup,
                            ),
                        }

                    traffic = derive_traffic_secrets(
                        shared_secret, SALT, CONTEXT
                    )
                    nonce = (
                        traffic.device_to_server_nonce_base
                        + (1).to_bytes(8, "big")
                    )
                    encrypted = aead_encrypt(
                        traffic.device_to_server_key,
                        nonce,
                        PAYLOAD,
                        AAD,
                    )
                    timings["aes_256_gcm_encrypt"] = measure(
                        lambda: aead_encrypt(
                            traffic.device_to_server_key,
                            nonce,
                            PAYLOAD,
                            AAD,
                        ),
                        iterations,
                        warmup,
                    )
                    timings["aes_256_gcm_decrypt"] = measure(
                        lambda: aead_decrypt(
                            traffic.device_to_server_key,
                            nonce,
                            encrypted,
                            AAD,
                        ),
                        iterations,
                        warmup,
                    )

                    client_transcript = build_client_auth_transcript(
                        kem_ciphertext,
                        "benchmark-device",
                        device_key_id,
                        transcript,
                    )

                    def complete_handshake() -> object:
                        ephemeral_public = server_kem.generate_keypair()
                        server_part = build_server_hello_transcript(
                            ephemeral_public,
                            SESSION_ID,
                            SALT,
                            identity_key_id(identity_public_key),
                        )
                        server_signature = signer.sign(server_part)
                        ciphertext, client_secret = client_kem.encap_secret(
                            ephemeral_public
                        )
                        if not verifier.verify(
                            server_part,
                            server_signature,
                            identity_public_key,
                        ):
                            raise RuntimeError("Handshake signature failed")
                        server_secret = server_kem.decap_secret(ciphertext)
                        if client_secret != server_secret:
                            raise RuntimeError("Handshake secrets differ")
                        client_part = build_client_auth_transcript(
                            ciphertext,
                            "benchmark-device",
                            device_key_id,
                            server_part,
                        )
                        device_signature = device_signer.sign(client_part)
                        if not verifier.verify(
                            client_part,
                            device_signature,
                            device_public_key,
                        ):
                            raise RuntimeError(
                                "Device handshake signature failed"
                            )
                        transcript_hash = handshake_transcript_hash(
                            server_part, client_part
                        )
                        return derive_traffic_secrets(
                            server_secret,
                            SALT,
                            build_info(SESSION_ID, transcript_hash),
                        )

                    timings["protocol_v3_mutual_auth_crypto_handshake"] = measure(
                        complete_handshake,
                        iterations,
                        warmup,
                    )

    return {
        "schema_version": SCHEMA_VERSION,
        "configuration": {
            "iterations": iterations,
            "warmup_iterations": warmup,
            "payload_bytes": len(PAYLOAD),
            "kem_algorithm": KEM_ALG,
            "signature_algorithm": SIGNATURE_ALG,
        },
        "environment": _environment(),
        "sizes_bytes": {
            "ml_kem_public_key": len(kem_public_key),
            "ml_kem_ciphertext": len(kem_ciphertext),
            "ml_kem_shared_secret": len(shared_secret),
            "ml_dsa_public_key": len(identity_public_key),
            "ml_dsa_signature": len(signature),
            "server_transcript": len(transcript),
            "client_transcript": len(client_transcript),
            "encrypted_payload": len(encrypted),
        },
        "timings": timings,
        "process_peak_rss_kib": _peak_rss_kib(),
        "interpretation": {
            "scope": "single-process cryptographic microbenchmark",
            "network_latency_included": False,
            "container_build_time_included": False,
            "warning": (
                "Compare results only on controlled, equivalently configured "
                "hardware and software."
            ),
        },
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark the PQC IoT protocol primitives."
    )
    parser.add_argument(
        "--iterations", type=int, default=DEFAULT_ITERATIONS
    )
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path; stdout is always populated.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    result = run_benchmarks(args.iterations, args.warmup)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
