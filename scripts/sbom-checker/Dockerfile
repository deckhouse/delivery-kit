FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4

RUN groupadd --gid 1000 checker && \
    useradd --uid 1000 --gid checker --create-home --shell /bin/sh checker

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=checker:checker . .

USER checker

ENTRYPOINT ["python", "sbom-checker.py"]
