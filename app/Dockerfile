FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 컨테이너 안에서 root 로 돌 이유가 없다
RUN useradd -m -u 1001 app && chown -R app:app /app
USER app

EXPOSE 8000
# 응답마다 붙는 server: uvicorn 을 뺀다. 콘솔 구성이 드러나지 않게 한다(이슈 #41).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]