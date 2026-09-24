# Backend + scanner image: the FastAPI app plus the security tools it
# executes (nmap, httpx, nuclei) with pinned versions.
#
# NOTE: containerization is a hardening layer, not a complete sandbox.
# Tools run as a non-root user with dropped capabilities; nmap is used in
# connect-scan mode (-sT), which needs no raw-socket capability.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap unzip curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pinned projectdiscovery tools (httpx + nuclei ship as release zips).
ARG HTTPX_VERSION=1.6.0
ARG NUCLEI_VERSION=3.3.7
RUN curl -sSL -o /tmp/httpx.zip \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/httpx.zip httpx -d /usr/local/bin \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip \
    && curl -sSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY agent_core ./agent_core
COPY backend ./backend
COPY alembic ./alembic

RUN pip install --no-cache-dir .

# Non-root execution; runs/ is the only writable volume (raw artifacts).
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/runs \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
