FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home ward && mkdir /state && chown ward /state
USER 10001:10001
ENV EMUWATCH_PUBLIC=1 EMUWATCH_STATE_DIR=/state PYTHONUNBUFFERED=1
EXPOSE 8794
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8794/healthz',timeout=2)"
CMD ["python", "-m", "emuwatch", "web", "--no-open", "--port", "8794"]
