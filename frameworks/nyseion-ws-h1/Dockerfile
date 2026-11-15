FROM rust:1.95-bookworm AS build
RUN rustup default nightly-2026-10-12
WORKDIR /app
# The nyseion-ws sources, copied in by `local-src.sh`.
COPY nyseion-ws ./nyseion-ws
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src/ target/release/httparena-nyseion-ws-h1* target/release/deps/httparena_nyseion_ws_h1*
COPY src ./src
RUN RUSTFLAGS="-C target-cpu=native" cargo build --release

FROM debian:bookworm-slim
COPY --from=build /app/target/release/httparena-nyseion-ws-h1 /server
# The harness mounts the certificate pair at /certs (server.crt, server.key); 8081 is the TLS listener.
EXPOSE 8080 8081
CMD ["/server"]
