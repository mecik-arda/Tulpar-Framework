# Tulpar — Cloud IAM Privilege Escalation Scanner
# Multi-stage Docker image for DevSecOps pipelines

# --- Build Stage ---
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Runtime Stage ---
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Tulpar Scanner"
LABEL org.opencontainers.image.description="Kurumsal Cloud IAM Yetki Yukseltme Tarayicisi"
LABEL org.opencontainers.image.source="https://github.com/mecik-arda/Tulpar-Framework"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="2.2.0"

RUN useradd --create-home --shell /bin/bash tulpar && \
    mkdir -p /app/raporlar && \
    chown -R tulpar:tulpar /app

COPY --from=builder /root/.local /home/tulpar/.local
COPY . /app/

WORKDIR /app
RUN pip install --no-cache-dir -e . && \
    chown -R tulpar:tulpar /app

USER tulpar
ENV PATH="/home/tulpar/.local/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

VOLUME ["/app/raporlar"]

ENTRYPOINT ["python", "-m", "tulpar"]
CMD ["--help"]
