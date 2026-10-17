# ==============================================================================
# VulnGraph Production Multi-Stage Dockerfile (Self-Contained Fullstack & DB)
# Supports:
#   1. Standalone deployment on Render/Railway/Fly (embedded FalkorDB)
#   2. Orchestrated deployment with Docker Compose (external FalkorDB)
# ==============================================================================

# ----------------- Stage 1: Build Dependencies -----------------
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ----------------- Stage 2: Production Runner -----------------
FROM python:3.11-slim AS runner

WORKDIR /app

# Install minimal runtime dependencies (curl for healthcheck, libgomp1/libssl3 for FalkorDB engine)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgomp1 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy FalkorDB Graph Engine & Redis binaries
COPY --from=falkordb/falkordb:latest /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY --from=falkordb/falkordb:latest /usr/local/bin/redis-cli /usr/local/bin/redis-cli
COPY --from=falkordb/falkordb:latest /var/lib/falkordb /var/lib/falkordb

# Create non-root system user and group
RUN groupadd -r -g 10001 appgroup && \
    useradd -r -u 10001 -g appgroup -d /app -s /sbin/nologin appuser && \
    mkdir -p /var/lib/falkordb/data && \
    chown -R appuser:appgroup /var/lib/falkordb

# Copy installed Python packages from builder stage
COPY --from=builder /root/.local /app/.local

# Ensure packages on PATH and Python knows app root
ENV PATH=/app/.local/bin:$PATH \
    PYTHONPATH=/app/backend:/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy application files with appuser ownership
COPY --chown=appuser:appgroup . .
RUN chmod +x /app/start.sh

# Set non-root user execution
USER 10001:10001

# Expose default port
EXPOSE 8000

# Default environment configuration (defaults to localhost for embedded FalkorDB)
ENV FALKORDB_HOST=localhost \
    FALKORDB_PORT=6379 \
    FALKORDB_GRAPH=vulngraph \
    API_PORT=8000 \
    API_HOST=0.0.0.0 \
    API_RELOAD=false

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/api/health || exit 1

# Production Entrypoint
CMD ["/app/start.sh"]
