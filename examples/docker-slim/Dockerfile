FROM debian:bookworm-slim

# Create app directory
WORKDIR /app

# Create runtime user and data directory
RUN useradd --system --uid 10001 --gid nogroup --home /app --shell /usr/sbin/nologin nop \
    && mkdir -p /data

# Copy the pre-built nop executable
COPY --chown=nop:nogroup nop /app/nop

# Fix ownership for runtime paths
RUN chown -R nop:nogroup /data /app

# Expose the app port
EXPOSE 5466

# Set entrypoint
USER nop:nogroup
ENTRYPOINT ["/app/nop", "-C", "/data", "-F"]
