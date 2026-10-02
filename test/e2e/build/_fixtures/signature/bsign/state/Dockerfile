FROM registry.werf.io/base/ubuntu:22.04 AS builder

FROM scratch

COPY --from=builder /usr/bin/true /usr/bin/true
COPY --from=builder /etc/os-release /etc/os-release
