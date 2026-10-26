FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY test/iec104/preflight/ ./test/iec104/preflight/
RUN GOFLAGS=-mod=mod CGO_ENABLED=0 go build -trimpath -o /out/preflight ./test/iec104/preflight

FROM alpine:3.22
RUN apk add --no-cache iproute2 nftables tcpdump
COPY --from=build /out/preflight /usr/local/bin/preflight
