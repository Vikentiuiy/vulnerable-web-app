FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8085
CMD ["gunicorn", "-w", "2", "--threads", "4", "-b", "0.0.0.0:8085", "--timeout", "120", "app:app"]
