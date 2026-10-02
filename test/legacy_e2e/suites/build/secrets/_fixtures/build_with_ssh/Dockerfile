FROM registry.werf.io/base/ubuntu:22.04

RUN apt-get update && \
    apt-get install -yq --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=ssh ssh-add -L && echo "SSH agent is available"

COPY file /file

RUN touch /created-by-run
