FROM debian:bookworm-slim

# Create app directory
WORKDIR /app

# Copy the pre-built nop executable
COPY nop /app/nop

# Create runtime root for the mounted volume
RUN mkdir -p /data

# Expose the app port
EXPOSE 5466

# Set entrypoint
ENTRYPOINT ["/app/nop", "-C", "/data", "-F"]
