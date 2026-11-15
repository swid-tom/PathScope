FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

RUN apt-get update && \
    apt-get install -y --no-install-recommends mtr-tiny iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app ./app
COPY config.example.yaml ./config.yaml

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
