FROM rust:1.95-bookworm AS build
RUN rustup default nightly-2026-10-12
WORKDIR /app
# The rimu-ws sources, copied in by `local-src.sh`.
COPY rimu-ws ./rimu-ws
COPY rimu-json ./rimu-json
COPY rimu-gzip ./rimu-gzip
COPY rimu-http1 ./rimu-http1
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src/ target/release/httparena-rimu-ws-h1* target/release/deps/httparena_rimu_ws_h1*
COPY src ./src
RUN RUSTFLAGS="-C target-cpu=native" cargo build --release

FROM debian:bookworm-slim
COPY --from=build /app/target/release/httparena-rimu-ws-h1 /server
# The harness mounts the certificate pair at /certs (server.crt, server.key); 8081 is the TLS listener.
EXPOSE 8080 8081
CMD ["/server"]
