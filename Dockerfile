# Pinned Python 3.12 slim image for reproducible builds.
ARG PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

FROM ${PYTHON_IMAGE} AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    OQS_INSTALL_PATH=/usr/local \
    PYOQS_VERSION=0.16.0
WORKDIR /build

ARG LIBOQS_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential pkg-config libssl-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --branch "${LIBOQS_VERSION}" --depth 1 \
      https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
  && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DCMAKE_INSTALL_LIBDIR=lib \
  && ninja -C /tmp/liboqs/build \
  && ninja -C /tmp/liboqs/build install \
  && test -f /usr/local/lib/liboqs.so \
  && rm -rf /tmp/liboqs

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY requirements.lock /build/requirements.lock
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
  && pip install --no-cache-dir --requirement /build/requirements.lock \
  && python -c "import oqs; assert oqs.oqs_version().startswith('0.16.0'), oqs.oqs_version()"


FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OQS_INSTALL_PATH=/usr/local \
    PYOQS_VERSION=0.16.0 \
    PATH="/opt/venv/bin:${PATH}"
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
  && rm -rf /var/lib/apt/lists/* \
  && /usr/local/bin/python -m pip uninstall -y setuptools \
  && /opt/venv/bin/python -m pip uninstall -y setuptools wheel \
  && groupadd --gid 10001 app \
  && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig

COPY --chown=app:app . /app
RUN mkdir -p /app/secrets /app/results \
  && chown -R app:app /app/secrets /app/results

USER 10001:10001

EXPOSE 9000

# Check that the process owns a listening socket on port 9000 without opening
# a connection and consuming the demo server's single protocol session.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "from pathlib import Path; import sys; files=('/proc/net/tcp','/proc/net/tcp6'); listening=any(any(line.split()[3]=='0A' and line.split()[1].endswith(':2328') for line in Path(name).read_text().splitlines()[1:]) for name in files if Path(name).exists()); sys.exit(0 if listening else 1)"

CMD ["python", "-m", "src.server.server_app"]
