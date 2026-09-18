FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# 공격을 직접 받는 컨테이너다. root 로 돌 이유가 없다.
RUN useradd -m -u 1002 decoy && mkdir -p /var/log/decoy && chown -R decoy:decoy /var/log/decoy
USER decoy

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
