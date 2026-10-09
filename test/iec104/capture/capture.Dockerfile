# Capture helper for test/iec104/capture/capture.sh only; never shipped in a
# product image. It runs tcpdump in the Docker host network namespace (the
# Linux VM on Docker Desktop), where the throwaway capture network's bridge
# lives, so it records the lib60870 traffic on that bridge.
ARG ALPINE_DIGEST=sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
FROM alpine:3.21@${ALPINE_DIGEST}
RUN apk add --no-cache tcpdump
ENTRYPOINT ["tcpdump"]
