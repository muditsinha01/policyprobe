# ──────────────────────────────────────────────
# Stage 1: Build Next.js frontend
# ──────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./

ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ──────────────────────────────────────────────
# Stage 2: Runtime image
# ──────────────────────────────────────────────
FROM python:3.11-slim

# Install Node.js 20 + supervisor
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        supervisor \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ──
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# ── Backend source ──
COPY backend/ ./backend/
COPY config/ ./config/

# ── Frontend: production deps + built output ──
COPY frontend/package*.json ./frontend/
COPY frontend/next.config.js  ./frontend/
COPY --from=frontend-builder /app/frontend/.next ./frontend/.next

WORKDIR /app/frontend
RUN npm ci --omit=dev

WORKDIR /app

# ── Supervisor config ──
COPY supervisord.conf /etc/supervisor/conf.d/policyprobe.conf

# Only the frontend port is exposed externally.
# The backend (5500) is accessed internally by the Next.js process.
EXPOSE 5001

ENV NEXT_TELEMETRY_DISABLED=1
# Tells the Next.js API route where to find the backend (same container)
ENV BACKEND_URL=http://127.0.0.1:5500

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
