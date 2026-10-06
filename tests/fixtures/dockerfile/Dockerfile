# syntax=docker/dockerfile:1
ARG RUST_VERSION=1.88
FROM rust:${RUST_VERSION} AS build
WORKDIR /src
COPY . .
RUN cargo build --release \
    # a comment inside a continuation
    && strip target/release/app

FROM debian:bookworm-slim
COPY --from=build /src/target/release/app /usr/local/bin/app
EXPOSE 8080
ENTRYPOINT ["app"]
