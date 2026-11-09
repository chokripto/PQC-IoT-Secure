FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    OQS_INSTALL_PATH=/usr/local \
    PYOQS_VERSION=0.16.0
WORKDIR /app

ARG LIBOQS_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential pkg-config \
    libssl-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Build the shared library required by liboqs-python. The explicit install
# directory prevents the wrapper from compiling a private copy at runtime.
RUN git clone --branch "${LIBOQS_VERSION}" --depth 1 \
      https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
  && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DCMAKE_INSTALL_LIBDIR=lib \
  && ninja -C /tmp/liboqs/build \
  && ninja -C /tmp/liboqs/build install \
  && ldconfig \
  && test -f /usr/local/lib/liboqs.so \
  && rm -rf /tmp/liboqs

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -U pip setuptools wheel \
  && pip install --no-cache-dir -r /app/requirements.txt \
  && python -c "import oqs; assert oqs.oqs_version().startswith('0.16.0'), oqs.oqs_version()"

COPY . /app

CMD ["python", "-m", "src.server.server_app"]
