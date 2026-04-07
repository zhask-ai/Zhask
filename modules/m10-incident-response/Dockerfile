# --- builder stage ---
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir .

# --- runtime stage ---
FROM python:3.12-slim
RUN useradd --create-home appuser
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY src/ /app/src/
COPY ../../shared/ /app/shared/
USER appuser
EXPOSE 8010
CMD ["uvicorn", "integrishield.m10.main:app", "--host", "0.0.0.0", "--port", "8010"]
