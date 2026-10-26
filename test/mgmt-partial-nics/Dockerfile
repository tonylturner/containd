FROM alpine:3.21
RUN apk add --no-cache nftables iproute2 curl ca-certificates unbound sqlite python3
COPY containd /usr/bin/containd
COPY entrypoint.sh /usr/local/bin/partial-nics-entrypoint
ENTRYPOINT ["/bin/sh", "/usr/local/bin/partial-nics-entrypoint"]
