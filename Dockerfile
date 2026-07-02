# WhisperWard OSINT - Dockerfile
# Phase 4 | Pixora Inc.

FROM python:3.11-slim-bookworm

# Metadata
LABEL maintainer="Pixora Inc." \
      description="WhisperWard OSINT - Public-signal threat hunting toolkit" \
      version="4.0"

# Create non-root user
RUN useradd -m -u 1000 whisperward

WORKDIR /app

# System dependencies: build tools and image libraries for Pillow/imagehash,
# curl for the container healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libjpeg-dev \
    zlib1g-dev \
    libpng-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Set proper permissions
RUN chown -R whisperward:whisperward /app

# Switch to non-root user
USER whisperward

# Expose FastAPI port
EXPOSE 8003

# Healthcheck against the API router, which is mounted under /api
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8003/api/health || exit 1

# Run the application. A single worker is deliberate: the app uses SQLite and
# seeds demo data on startup when the database is empty; multiple workers would
# race the seed guard and can contend on the SQLite file. Scale with replicas
# behind a load balancer if needed, not with in-process workers.
CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8003", "--workers", "1"]
