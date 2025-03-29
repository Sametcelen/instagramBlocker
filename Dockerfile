FROM python:3.9-slim

WORKDIR /app

# Önce bağımlılıkları kur (cache için)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sonra diğer dosyaları kopyala
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Chromium + Chrome Driver kurulumu
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    wget \
    unzip \
    curl \
    && wget https://chromedriver.storage.googleapis.com/LATEST_RELEASE -O /tmp/chromedriver_version \
    && CHROME_DRIVER_VERSION=$(cat /tmp/chromedriver_version) \
    && wget https://chromedriver.storage.googleapis.com/${CHROME_DRIVER_VERSION}/chromedriver_linux64.zip \
    && unzip chromedriver_linux64.zip -d /usr/bin/ \
    && rm chromedriver_linux64.zip \
    && chmod +x /usr/bin/chromedriver \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:${PORT:-5000}/ || exit 1

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120 app:app"]