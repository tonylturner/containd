# syntax=docker/dockerfile:1
# Native arm64 only. Package pins intentionally fail rather than drift.
FROM golang:1.26.10-alpine@sha256:53a4760b868cdf087312b1f478bce6ca05a48e6bbab8402c885e1a478c9500ed AS build
WORKDIR /src
COPY *.go ./
RUN CGO_ENABLED=0 GOFLAGS=-mod=mod go build -trimpath -ldflags='-s -w' -o /perf main.go load.go protocol.go
FROM alpine:3.23.2@sha256:410dabcd6f1d53f1f4e5c1ce9553efa298ca6bcdd086dfc976b8f659d58b46d2
RUN apk add --no-cache iproute2=6.17.0-r0 tcpdump=4.99.5-r1 ethtool=6.15-r0 tini=0.19.0-r3
COPY --from=build /perf /usr/local/bin/perf
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/perf"]
