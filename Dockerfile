# Linux environment for real namespace isolation.
#   docker build -t os-sandbox .
#   docker run --rm -it --privileged os-sandbox sandbox shell --hostname guest
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tests ./tests
RUN pip install --no-cache-dir -e ".[dev]"
CMD ["sandbox", "demo"]
