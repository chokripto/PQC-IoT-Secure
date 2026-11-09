# Reproducible IoT benchmarks

The benchmark harness measures the cryptographic work used by protocol v2. It
is intended for repeatable engineering comparisons, not marketing claims or a
substitute for measurements on the target microcontroller.

## Measured operations

- ML-KEM-768 key generation, encapsulation, and decapsulation;
- ML-DSA-65 key generation, signing, and verification;
- HKDF-SHA-256 directional traffic-secret derivation;
- AES-256-GCM encryption and decryption of the fixed telemetry payload;
- the complete protocol-v2 cryptographic handshake, excluding network I/O.

Each operation is warmed up before measurement. Garbage collection is disabled
only during the timed samples. Every sample uses
`time.perf_counter_ns()`. Results include minimum, median, arithmetic mean,
nearest-rank p95, and maximum times in nanoseconds.

## Run in the pinned Docker environment

Build once:

```bash
docker build -t pqc-iot-secure .
```

Linux or macOS:

```bash
mkdir -p results
docker run --rm \
  -v "$PWD/results:/results" \
  pqc-iot-secure \
  python -m scripts.benchmark_iot \
  --iterations 100 --warmup 10 \
  --output /results/benchmark.json
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force results
docker run --rm `
  -v "${PWD}/results:/results" `
  pqc-iot-secure `
  python -m scripts.benchmark_iot `
  --iterations 100 --warmup 10 `
  --output /results/benchmark.json
```

The JSON file records the algorithm names, workload, key and message sizes,
Python and liboqs versions, operating system, architecture, visible CPU count,
timer resolution, process peak RSS, and all timing distributions.

## Comparison protocol

For defensible comparisons:

1. use the same commit, Docker image, iteration count, and warm-up count;
2. run on otherwise idle hardware with a stable power/performance profile;
3. record the exact CPU model and Docker resource limits outside the JSON;
4. perform at least five independent process runs;
5. compare medians and p95 values, not the single fastest sample;
6. retain the original JSON files with the report;
7. benchmark on the real IoT target before making deployment claims.

GitHub-hosted runners are used only as a functional smoke test. Their timing
results are not stable enough to serve as published performance evidence.

## Scope and limitations

`process_peak_rss_kib` is the process high-water mark reported by the
operating system. It is not an isolated per-operation allocation measurement.
The complete-handshake measurement excludes sockets, serialization, container
startup, provisioning, and network latency. Results from different hardware,
operating systems, power modes, or liboqs builds are not directly comparable.
