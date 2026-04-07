FROM python:3.13-slim

WORKDIR /workspace

COPY apps/dashboard/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /workspace

EXPOSE 8787

CMD ["python", "apps/dashboard/backend/server.py"]
