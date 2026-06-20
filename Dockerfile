# Tulpar — Cloud IAM Privilege Escalation Scanner
# Multi-stage Docker image for DevSecOps pipelines

# --- Build Stage ---
FROM python:3.11-slim AS builder

WORKDIR /app
COPY . .
RUN pip install --upgrade pip wheel setuptools && \
    pip wheel --no-cache-dir --wheel-dir /app/wheels .

# --- Runtime Stage ---
FROM python:3.11-slim

# OS zafiyetlerini (perl, sqlite3, ncurses vb.) gidermek icin guncelleme
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="Tulpar Scanner"
LABEL org.opencontainers.image.description="Kurumsal Cloud IAM Yetki Yukseltme Tarayicisi"
LABEL org.opencontainers.image.source="https://github.com/mecik-arda/Tulpar-Framework"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="3.0.0"

RUN useradd --create-home --shell /bin/bash tulpar && \
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
