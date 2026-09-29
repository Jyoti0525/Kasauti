# Kasauti in one container: the web UI, the API and its audit workers, with SQLite on the
# container's own disk. Build from the repository root:
#
#     docker build -f deploy/Dockerfile -t kasauti .
#     docker run -p 8000:8000 -e KASAUTI_PUBLIC_URL=https://kasauti.example.org kasauti
#
# Render builds it from render.yaml. Base images are pinned by version and the Python
# dependencies by uv.lock (uv sync --frozen); the web UI's by package-lock.json (npm ci).

FROM node:20.19-bookworm-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npx vite build

FROM python:3.12.8-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv
RUN useradd --create-home --uid 1000 kasauti
USER kasauti
ENV HOME=/home/kasauti \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    UV_FROZEN=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    PATH=/home/kasauti/app/.venv/bin:$PATH
WORKDIR /home/kasauti/app
COPY --chown=kasauti pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY --chown=kasauti backend/kasauti ./backend/kasauti
RUN uv sync --no-dev
COPY --chown=kasauti packs ./packs
COPY --chown=kasauti datasets/authored ./datasets/authored
COPY --chown=kasauti tools/demo_seed.py ./tools/demo_seed.py
COPY --chown=kasauti deploy/start.py ./deploy/start.py
COPY --chown=kasauti --from=web /src/frontend/dist ./frontend/dist

EXPOSE 8000
CMD ["python", "deploy/start.py"]
