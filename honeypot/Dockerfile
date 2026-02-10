FROM python:3.11-slim

WORKDIR /app
COPY honeypot.py .
COPY logger.py .

RUN mkdir -p /app/logs

EXPOSE 22

CMD ["python3", "honeypot.py"]