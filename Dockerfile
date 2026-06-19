# WebFilter Proxy — runs the filtering proxy (8080) and the management UI (8000)
# in a single container. Both processes are launched by start.sh.
FROM python:3.12-slim

# Runtime libraries needed by the optional image classifier (NudeNet → OpenCV)
# and by Pillow. Installed unconditionally so the NSFW image filter works
# out of the box; they are small relative to the ML model itself.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        libgl1 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first so the layer is cached across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY proxy ./proxy
COPY management ./management
COPY shared ./shared
COPY scripts ./scripts
COPY config ./config
COPY policies ./policies
COPY categories ./categories
COPY start.sh CLAUDE.md README.md ./

# These hold state and are meant to be mounted as volumes (see compose file).
RUN mkdir -p certs logs models

# Release tag stamped in at build time (CI passes the git tag); the management
# UI reports this. Defaults to "dev" for local `docker build` / `compose build`.
ARG VERSION=dev
ENV WEBFILTER_VERSION=$VERSION

# 8080 = filtering proxy · 8000 = management UI
EXPOSE 8080 8000

# start.sh picks the system python (no ./runtime or ./.venv in the image),
# launches the management API, then mitmproxy, and forwards signals.
CMD ["bash", "start.sh"]
