FROM rust:1.95-bookworm AS build
RUN rustup default nightly-2026-10-12
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src/ target/release/httparena-rimu-ws* target/release/deps/httparena_rimu_ws*
COPY src ./src
RUN RUSTFLAGS="-C target-cpu=native" cargo build --release

FROM debian:bookworm-slim
COPY --from=build /app/target/release/httparena-rimu-ws /server
EXPOSE 8080
CMD ["/server"]
