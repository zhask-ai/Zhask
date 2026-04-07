FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir redis==5.2.1

COPY shared/ /app/shared/
COPY poc/seed-injector/inject.py /app/inject.py

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/inject.py"]
