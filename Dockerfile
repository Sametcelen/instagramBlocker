# 1. Temel imaj: Python 3.9 slim
FROM python:3.9-slim

# 2. Çalışma dizinini ayarla
WORKDIR /app

# 3. Sistem bağımlılıklarını kur (Chrome, Chromium ve diğer gerekli araçlar)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    curl \
    libglib2.0-0 \
    libnss3 \
    libgconf-2-4 \
    libfontconfig1 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    libgbm-dev \
    chromium \
    chromium-driver \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 4. Proje dosyalarını kopyala
COPY . /app

# 5. Python bağımlılıklarını kur
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# 6. Ortam değişkenlerini ayarla
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

# 7. Sağlık kontrolü: $PORT runtime’da çözülecek
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:"$PORT"/ || exit 1

# 8. Gunicorn ile Flask uygulamasını başlat
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--workers", "2", "--timeout", "120", "app:app"]
