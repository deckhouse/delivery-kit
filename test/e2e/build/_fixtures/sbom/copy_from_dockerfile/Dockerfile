FROM registry.werf.io/base/alpine AS source

FROM registry.werf.io/base/ubuntu:22.04

COPY --from=source /etc/alpine-release /copied/alpine-release
COPY --from=source /etc/ssl/ /copied/ssl/

RUN touch /created-by-run
