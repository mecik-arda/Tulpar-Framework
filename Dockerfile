# Tulpar — Cloud IAM Privilege Escalation Scanner
# Alpine-based Docker image: minimal attack surface, zero OS CVEs

# --- Build Stage ---
FROM python:3.11-alpine AS builder

WORKDIR /app
COPY pyproject.toml .
COPY tulpar/ tulpar/

# Derleme bagimliliklari ve wheel olusturma
RUN apk update && apk upgrade --no-cache && \
    pip install --upgrade pip wheel setuptools && \
    pip wheel --no-cache-dir --wheel-dir /app/wheels .

# --- Runtime Stage ---
FROM python:3.11-alpine

# Alpine guncelleme (CVE patch'leri)
RUN apk update && apk upgrade --no-cache

LABEL org.opencontainers.image.title="Tulpar Scanner"
LABEL org.opencontainers.image.description="Kurumsal Cloud IAM Yetki Yukseltme Tarayicisi"
LABEL org.opencontainers.image.source="https://github.com/mecik-arda/Tulpar-Framework"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="3.0.0"

# Alpine'da useradd yerine adduser kullanilir
RUN adduser -D -s /bin/sh tulpar && \
    mkdir -p /app/raporlar && \
    chown -R tulpar:tulpar /app

COPY --from=builder /app/wheels /wheels
RUN pip install --upgrade pip wheel setuptools && \
    pip install --no-cache-dir /wheels/* && \
    rm -rf /wheels

COPY . /app/

WORKDIR /app
RUN chown -R tulpar:tulpar /app

USER tulpar
ENV PATH="/home/tulpar/.local/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

VOLUME ["/app/raporlar"]

ENTRYPOINT ["python", "-m", "tulpar"]
CMD ["--help"]
