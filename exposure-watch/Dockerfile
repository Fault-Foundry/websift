FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --gid 10001 scanner && useradd --uid 10001 --gid scanner --no-create-home scanner && mkdir /app/data && chown scanner:scanner /app/data
COPY scanner.py /app/scanner.py
USER 10001:10001
ENTRYPOINT ["python", "scanner.py"]
CMD ["--config", "/app/config.json", "--data", "/app/data", "--watch"]
