FROM rust:1.95-bookworm AS build
RUN rustup default nightly-2026-10-12
WORKDIR /app
# The nyseion-ws sources, copied in by `local-src.sh`.
COPY nyseion-ws ./nyseion-ws
COPY nyseion-quic ./nyseion-quic
COPY nyseion-qpack ./nyseion-qpack
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src/ target/release/httparena-nyseion-ws* target/release/deps/httparena_nyseion_ws*
COPY src ./src
RUN RUSTFLAGS="-C target-cpu=native" cargo build --release

FROM debian:bookworm-slim
COPY --from=build /app/target/release/httparena-nyseion-ws /server
EXPOSE 8080 8082 8443 8443/udp
CMD ["/server"]
