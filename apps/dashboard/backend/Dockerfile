FROM python:3.12-slim

WORKDIR /workspace

COPY apps/dashboard/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /workspace

ENV PYTHONPATH=/workspace

# Demo POC defaults — no Redis / microservices required; synthetic feeds + stubs
ENV INTEGRISHIELD_POC_MODE=1
ENV DEMO_GENERATOR=1
ENV M16_SERVICE_URL=

EXPOSE 8787

# Allow PORT override from hosting platform (Render, Railway, etc.)
ENV PORT=8787

CMD ["python3", "apps/dashboard/backend/server.py"]
