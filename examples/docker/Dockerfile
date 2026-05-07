# syntax=docker/dockerfile:1
FROM rust:1.88 as builder
WORKDIR /app
COPY scripts ./scripts
COPY nop ./nop
RUN ./scripts/crg.sh nop build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN useradd --system --uid 10001 --gid nogroup --home /app --shell /usr/sbin/nologin nop \
    && mkdir -p /data
COPY --from=builder --chown=nop:nogroup /app/nop/target/release/nop ./nop
RUN chown -R nop:nogroup /data /app
USER nop:nogroup
EXPOSE 5466
CMD ["./nop", "-C", "/data", "-F"]
