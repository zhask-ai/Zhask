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
USER appuser
EXPOSE 8012
CMD ["uvicorn", "integrishield.m12.main:app", "--host", "0.0.0.0", "--port", "8012"]
