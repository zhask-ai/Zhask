# M01 — API Gateway Shield
# Multi-stage build: keeps the final image lean.

FROM python:3.12-slim AS base

WORKDIR /app

# System deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cached layer unless requirements change)
COPY modules/m01-api-gateway-shield/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy shared library (Dev 1 owns, available to all modules)
COPY shared/ /app/shared/

# Copy M01 source
COPY modules/m01-api-gateway-shield/src/ /app/src/

# Set PYTHONPATH so both `shared` and the `integrishield` namespace resolve
ENV PYTHONPATH=/app:/app/src

EXPOSE 8000

CMD ["uvicorn", "integrishield.m01.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-level", "warning"]
