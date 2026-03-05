# remnawave-sync — VyOS container image
FROM debian:bookworm-slim

# Install runtime deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 python3-pip iproute2 ca-certificates curl \
    && pip3 install --no-cache-dir textual \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python source
COPY src/ /app/src/
COPY config.env.example /app/

# Create empty __init__.py for package resolution
RUN touch /app/__init__.py /app/src/__init__.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Default config location (override via volume)
ENV REMNAWAVE_CONFIG=/etc/remnawave/config.env

# Directories that should be volume-mounted
VOLUME ["/etc/remnawave", "/etc/sing-box", "/var/log/remnawave"]

ENTRYPOINT ["python3", "/app/src/daemon.py"]
CMD ["--config", "/etc/remnawave/config.env"]
