FROM python:3.12-slim

WORKDIR /app

COPY modules/m08-anomaly-detection/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY shared/ /app/shared/
COPY ml/__init__.py /app/ml/__init__.py
COPY ml/training/__init__.py /app/ml/training/__init__.py
COPY ml/training/feature_engineering.py /app/ml/training/feature_engineering.py
# Model is mounted at runtime via docker-compose volume
COPY modules/m08-anomaly-detection/ /app/modules/m08-anomaly-detection/

WORKDIR /app/modules/m08-anomaly-detection

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
