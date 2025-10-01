FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 50053

CMD ["python", "main.py", "--host", "[::]", "--port", "50053"]