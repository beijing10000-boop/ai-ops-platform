FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
# Slow links to PyPI time out mid-download; PIP_INDEX_URL (from .env) selects a mirror.
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir --default-timeout=120 --retries 10 -r requirements.txt
COPY app/ ./app/
COPY web/ ./web/
RUN mkdir -p /app/data \
    && chmod -R a+rX /app/app /app/web \
    && chown -R 10001:10001 /app/data
USER 10001
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8088"]
