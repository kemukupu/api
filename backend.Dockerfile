FROM rust:latest

WORKDIR /app

COPY . .

RUN cargo build --release

RUN apt-get update \
    && apt-get install -y postgresql cmake \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install diesel_cli --no-default-features --features postgres

ENV ROCKET_HOST 0.0.0.0
ENV ROCKET_PORT 3000

EXPOSE 3000

ENTRYPOINT ["/app/docker_entrypoint.sh"]