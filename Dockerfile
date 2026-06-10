FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY detector.py dashboard.py ./

RUN touch /app/alerts.log

CMD ["python3", "-u", "detector.py"]
