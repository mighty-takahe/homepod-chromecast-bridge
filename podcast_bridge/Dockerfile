FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PODCAST_DATA_DIR=/data \
    PODCAST_WEB_PORT=8788

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    avahi-daemon \
    libavahi-compat-libdnssd-dev \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY run.sh /app/run.sh

RUN chmod +x /app/run.sh && mkdir -p /data

EXPOSE 8788 8009 8010 8011 18008 18009 18010

CMD ["/app/run.sh"]
