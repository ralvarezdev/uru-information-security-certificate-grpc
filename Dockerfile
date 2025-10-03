FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN apt-get update && \
    apt-get install -y libpq5 libpq-dev gcc build-essential python3-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y libpq-dev gcc build-essential python3-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 50053

CMD ["python", "main.py", "--host", "[::]", "--port", "50053"]