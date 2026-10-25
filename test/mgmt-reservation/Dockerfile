FROM alpine:3.21
RUN apk add --no-cache nftables iproute2 curl ca-certificates unbound
COPY containd /usr/bin/containd
ENTRYPOINT ["/usr/bin/containd"]
CMD ["all"]
