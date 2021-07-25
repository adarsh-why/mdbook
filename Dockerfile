FROM rust:latest

RUN cargo install mdbook

FROM debian:buster-slim
COPY --from=0 /usr/local/cargo/bin/mdbook /usr/local/bin/mdbook

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT "/entrypoint.sh"
