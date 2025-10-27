# Multi-stage build for optimized image size
# Stage 1: Builder
FROM python:3.13-slim AS builder

# Set build arguments
ARG BUILDKIT_INLINE_CACHE=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Stage 2: Runtime
FROM python:3.13-slim

# Set metadata
LABEL maintainer="RAVERSE Team"
LABEL description="AI Multi-Agent Binary Patching System"
LABEL version="2.0.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r raverse && useradd -r -g raverse raverse

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY agents/ /app/agents/
COPY main.py /app/main.py
COPY utils/ /app/utils/
COPY config/ /app/config/

# Create necessary directories
RUN mkdir -p /app/binaries /app/logs /app/output && \
    chown -R raverse:raverse /app

# Switch to non-root user
USER raverse

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "main.py"]

