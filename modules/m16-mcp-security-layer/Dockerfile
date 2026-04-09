# M16 — MCP Security Layer (POC stub)
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.115.5 uvicorn[standard]==0.32.1 redis==5.0.8

COPY shared/ /app/shared/
COPY modules/m16-mcp-security-layer/src/ /app/src/

ENV PYTHONPATH=/app:/app/src
ENV PYTHONUNBUFFERED=1

EXPOSE 8016

CMD ["uvicorn", "integrishield.m16.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8016", \
     "--log-level", "warning"]
