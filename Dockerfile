# ─── Stage 1: Build ──────────────────────────────────────────────────────────
FROM rust:1.90-slim-bookworm AS builder

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests for dependency caching
COPY Cargo.toml Cargo.lock ./
# Create a dummy main to build dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm src/main.rs

# Copy real source
COPY src/ src/
# Update timestamp to trigger rebuild
RUN touch src/main.rs
RUN cargo build --release

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

WORKDIR /opt/sentinel-claw

# Install runtime dependencies (OpenSSL, etc)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/sentinel ./sentinel

# Environment labels
LABEL maintainer="Morravex"
LABEL description="SentinelClaw v0.0.1: Universal Sentinel Proxy Gateway"

# Default Ports
EXPOSE 8080 8081 8082

# Runtime environment (UDS and TCP)
ENV SENTINEL_SOCKET_PATH=/tmp/sentinel.sock

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Entrypoint
CMD ["./sentinel"]
