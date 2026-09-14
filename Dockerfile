FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Create a dedicated non-root application user
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
# Download the large ML model from GitHub Release
ARG MODEL_URL="https://github.com/ArunRajoriya/PhishGuard-AI/releases/download/v2.2.0-model/domain_url_model.pkl"
ARG MODEL_SHA256="0ad0ef7913093188148a96d213922cd17314471630932bf394d71483ffa4d30e"

RUN mkdir -p /app/model \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fL --retry 3 --retry-delay 2 \
        -o /app/model/domain_url_model.pkl \
        "$MODEL_URL" \
    && echo "$MODEL_SHA256  /app/model/domain_url_model.pkl" | sha256sum -c -