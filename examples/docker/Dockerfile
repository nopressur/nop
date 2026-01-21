# syntax=docker/dockerfile:1
FROM rust:1.76 as builder
WORKDIR /app
COPY ../scripts ./scripts
COPY ../nop ./nop
RUN ./scripts/cargo.sh build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/nop/target/release/nop ./nop
RUN mkdir -p /data
EXPOSE 5466
CMD ["./nop", "-C", "/data", "-F"]
