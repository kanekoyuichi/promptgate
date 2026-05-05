FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir promptgate

COPY . .

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
