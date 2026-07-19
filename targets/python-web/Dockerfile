FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping libxml2 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /app/data && \
    echo "TOP-SECRET: flag{python_path_traversal_works}" > /app/secret.txt && \
    echo "public sample" > /app/data/sample.txt
COPY . .
EXPOSE 8082
CMD ["gunicorn", "-w", "2", "--threads", "4", "-b", "0.0.0.0:8082", "--timeout", "120", "app:app"]
