FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

ARG LIBOQS_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential pkg-config \
    libssl-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Keep liboqs and liboqs-python on matching release lines.
RUN git clone --branch "${LIBOQS_VERSION}" --depth 1 \
      https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
  && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
  && ninja -C /tmp/liboqs/build \
  && ninja -C /tmp/liboqs/build install \
  && ldconfig \
  && rm -rf /tmp/liboqs

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -U pip setuptools wheel \
  && pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

CMD ["python", "-m", "src.server.server_app"]
