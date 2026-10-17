# Build micromail from source, then run it from a minimal image.
FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/micromail /usr/local/bin/micromail
COPY .hostorca/entrypoint.sh /usr/local/bin/micromail-entrypoint
RUN chmod 0755 /usr/local/bin/micromail-entrypoint

# The spool and DKIM keys are the only state worth keeping.
VOLUME /data
EXPOSE 587 465 8080
ENTRYPOINT ["micromail-entrypoint"]
CMD ["serve"]
