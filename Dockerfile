FROM python:3.11-slim

LABEL maintainer="Zparty" \
      description="Automated Web Penetration Testing Framework" \
      version="1.0"

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    dnsutils \
    git \
    # Playwright system deps (chromium)
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# ── App setup ─────────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (chromium only for size)
RUN python -m playwright install chromium --with-deps 2>/dev/null || \
    echo "Playwright chromium install skipped (optional)"

COPY . .

# ── Volumes ───────────────────────────────────────────────────────────────────
# Mount your results dir, wordlists, and config from outside the container.
VOLUME ["/app/results", "/app/wordlists", "/app/config"]

# ── Default command ───────────────────────────────────────────────────────────
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
