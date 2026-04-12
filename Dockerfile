# Stage 1: Build
FROM rust:1.90-slim-bookworm AS builder

# Install system dependencies + gcc for C shim
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libssl-dev build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests for dependency caching
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm src/main.rs

# Copy real source
COPY src/ src/
COPY shim/ shim/

# Build C shim
RUN gcc -shared -fPIC -O2 -Wall \
    -o shim/build/libsentry_scrub.so \
    shim/sentinel_scrub.c -ldl -lpthread

# Build Rust binary
RUN touch src/main.rs
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for runtime
RUN groupadd -r sentinel && useradd -r -g sentinel -d /opt/sentinel-claw sentinel

WORKDIR /opt/sentinel-claw

# Copy binary and shim from builder
COPY --from=builder /app/target/release/sentinel ./sentinel
COPY --from=builder /app/shim/build/libsentry_scrub.so ./shim/build/libsentry_scrub.so

# Create directories sentinel needs
RUN mkdir -p shim/build && \
    chown -R sentinel:sentinel /opt/sentinel-claw

LABEL maintainer="Morravex"
LABEL description="SentinelClaw v0.0.1: Universal Sentinel Proxy Gateway"

# Expose all agent ports + dashboard
EXPOSE 8080-8089 3333

ENV SENTINEL_SOCKET_PATH=/tmp/sentinel.sock

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Run as non-root (except for kernel-level features which need host-level setup)
# The sentinel binary itself can run non-root; only `sentinel run` needs root on the HOST.
USER sentinel

CMD ["./sentinel"]
