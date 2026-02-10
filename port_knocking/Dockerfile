FROM python:3.11-slim

RUN apt-get update && apt-get install -y iptables netcat-openbsd && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY knock_server.py .
COPY knock_client.py .
COPY demo.sh .
RUN chmod +x demo.sh

CMD ["python3", "knock_server.py"]