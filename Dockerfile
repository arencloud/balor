# syntax=docker/dockerfile:1

########################################
# Builder: compile admin WASM and backend
########################################
FROM rust:1.77-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates curl build-essential \
 && rm -rf /var/lib/apt/lists/*

# Trunk + wasm target for the Yew admin UI
RUN rustup target add wasm32-unknown-unknown && \
    cargo install trunk

WORKDIR /app
COPY . .

# Build the admin UI (outputs to admin/dist)
RUN cd admin && trunk build --release

# Build the backend binary
RUN cargo build -p backend --release

########################################
# Runtime image
########################################
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV BALOR_ADMIN_DIST=/app/admin/dist \
    BALOR_HTTP_ADDR=0.0.0.0:9443

WORKDIR /app
COPY --from=builder /app/target/release/backend /usr/local/bin/balor
COPY --from=builder /app/admin/dist /app/admin/dist
COPY data /app/data

EXPOSE 9443

ENTRYPOINT ["/usr/local/bin/balor"]
