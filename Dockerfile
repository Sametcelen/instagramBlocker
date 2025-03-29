# Base image: Python 3.9 slim
FROM python:3.9-slim

# Çalışma dizinini /app olarak ayarla
WORKDIR /app

# Proje dosyalarını kopyala
COPY . /app

# Sistem bağımlılıklarını kur (Chromium ve gerekli araçlar)
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Python bağımlılıklarını kur
RUN pip install --no-cache-dir -r requirements.txt

# Python çıktılarını tamponlama
ENV PYTHONUNBUFFERED=1

# Sağlık kontrolü
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:$PORT/ || exit 1

# Gunicorn ile Flask uygulamasını başlat
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--workers", "2", "--timeout", "120", "app:app"]
