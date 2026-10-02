FROM registry.werf.io/base/alpine
ARG NETWORK_PROBE_URL
RUN wget -T 5 -O /tmp/network-probe "$NETWORK_PROBE_URL" && \
    grep -qx 'network available' /tmp/network-probe && \
    echo 'network probe succeeded'
