FROM python:3.12-slim

WORKDIR /app

COPY modules/m11-shadow-integration/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY shared/ /app/shared/
COPY modules/m11-shadow-integration/ /app/modules/m11-shadow-integration/

WORKDIR /app/modules/m11-shadow-integration

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
