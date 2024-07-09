FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y build-essential pkg-config libssl-dev

COPY . /app

WORKDIR /app
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y tcpdump curl net-tools iproute2 procps
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /app/target/release/vrrp-test /usr/bin/vrrp-test
COPY --from=builder /app/entrypoint.sh /entrypoint.sh

WORKDIR /etc
ENV RUST_LOG=info
ENTRYPOINT [ "/entrypoint.sh" ]
