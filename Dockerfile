FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir "promptgate" "fastapi>=0.111" "uvicorn[standard]>=0.29"

COPY app.py .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
