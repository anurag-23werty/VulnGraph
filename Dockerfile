# ==============================================================================
# VulnGraph Production Multi-Stage Dockerfile
# Stage 1: Dependency Builder
# Stage 2: Hardened Non-Root Minimal Runtime
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

# Create non-root system user and group
RUN groupadd -r -g 10001 appgroup && \
    useradd -r -u 10001 -g appgroup -d /app -s /sbin/nologin appuser

# Install minimal runtime dependencies (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /root/.local /app/.local

# Ensure packages on PATH and Python knows app root
ENV PATH=/app/.local/bin:$PATH \
    PYTHONPATH=/app/backend:/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy application files with appuser ownership
COPY --chown=appuser:appgroup . .

# Set non-root user execution
USER 10001:10001

# Expose FastAPI Web UI & API port
EXPOSE 8000

# Default environment configuration
ENV FALKORDB_HOST=falkordb \
    FALKORDB_PORT=6379 \
    FALKORDB_GRAPH=vulngraph \
    API_PORT=8000 \
    API_HOST=0.0.0.0 \
    API_RELOAD=false

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Production Entrypoint
CMD ["python", "backend/main.py"]
