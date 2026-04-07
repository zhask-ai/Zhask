FROM python:3.12-slim

WORKDIR /app

COPY modules/m09-dlp/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY shared/ /app/shared/
COPY modules/m09-dlp/ /app/modules/m09-dlp/

WORKDIR /app/modules/m09-dlp

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
