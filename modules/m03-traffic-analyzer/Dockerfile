FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY modules/m03-traffic-analyzer/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy repo structure needed at runtime
COPY shared/ /app/shared/
COPY ml/training/feature_engineering.py /app/ml/training/feature_engineering.py
COPY ml/__init__.py /app/ml/__init__.py
COPY ml/training/__init__.py /app/ml/training/__init__.py
COPY modules/m03-traffic-analyzer/ /app/modules/m03-traffic-analyzer/

WORKDIR /app/modules/m03-traffic-analyzer

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
