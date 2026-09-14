FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install Python dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# ML model hosted as a GitHub Release asset
ARG MODEL_URL="https://github.com/ArunRajoriya/PhishGuard-AI/releases/download/v2.2.0-model/domain_url_model.pkl"
ARG MODEL_SHA256="0ad0ef7913093188148a96d213922cd17314471630932bf394d71483ffa4d30e"

# Download and verify the model
RUN mkdir -p /app/model \
    && python -c "import urllib.request; urllib.request.urlretrieve('${MODEL_URL}', '/app/model/domain_url_model.pkl')" \
    && echo "${MODEL_SHA256}  /app/model/domain_url_model.pkl" | sha256sum -c -

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]   