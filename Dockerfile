FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Default environment variables
ENV FALKORDB_HOST=falkordb
ENV FALKORDB_PORT=6379
ENV FALKORDB_GRAPH=vulngraph
ENV API_PORT=8000
ENV API_HOST=0.0.0.0

# Start server
CMD ["python", "main.py"]
