FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p foliora-sync-service

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/foliora-sync-service /usr/local/bin/foliora-sync-service
USER 65532:65532
EXPOSE 8787
ENTRYPOINT ["foliora-sync-service"]
