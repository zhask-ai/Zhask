# M14 — Webhook Gateway (POC stub)
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.115.5 uvicorn[standard]==0.32.1 redis==5.0.8

COPY shared/ /app/shared/
COPY modules/m14-webhook-gateway/src/ /app/src/

ENV PYTHONPATH=/app:/app/src
ENV PYTHONUNBUFFERED=1

EXPOSE 8014

CMD ["uvicorn", "integrishield.m14.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8014", \
     "--log-level", "warning"]
