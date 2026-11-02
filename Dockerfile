FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home ward && mkdir /state && chown ward /state
USER 10001:10001
ENV WARD_PUBLIC=1 WARD_STATE_DIR=/state PYTHONUNBUFFERED=1
EXPOSE 8794
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8794/healthz',timeout=2)"
CMD ["python", "-m", "ward", "web", "--no-open", "--port", "8794"]
