FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=10000

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p database model static/images templates

# Ensure model exists or train if needed
RUN if [ ! -f model/model.pkl ]; then python model/train_model.py; fi

# Create non-root user for security
RUN useradd -m -u 1000 phishguard && \
    chown -R phishguard:phishguard /app

USER phishguard

# Expose port
EXPOSE 10000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:10000/health', timeout=5)"

# Run application (Render sets PORT automatically)
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1