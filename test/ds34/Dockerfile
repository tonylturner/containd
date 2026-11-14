FROM alpine:3.23
RUN apk add --no-cache nftables iproute2 curl ca-certificates python3 tcpdump strace sqlite unbound
COPY containd /usr/bin/containd
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
