# WhisperWard OSINT - Dockerfile
# Phase 4 Milestone 0 | Pixora Inc.

FROM python:3.11-slim-bookworm

# Metadata
LABEL maintainer="Pixora Inc." \
      description="WhisperWard OSINT - Public-signal threat hunting toolkit" \
      version="4.0"

# Create non-root user
RUN useradd -m -u 1000 whisperward

WORKDIR /app

# Install system dependencies (needed for Pillow, imagehash, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libjpeg-dev \
    zlib1g-dev \
    libpng-dev \
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

# Healthcheck (good practice)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8003/health || exit 1

# Run the application
CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8003", "--workers", "2"]