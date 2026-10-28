FROM golang:1.26.10@sha256:24a707af49702fa44f02785475d02fb752f6982d3e9c0afb7696e1f0204e7ce9
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev=1.10.5-2 tcpdump=4.99.5-2 && apt-get clean
WORKDIR /src
ADD source.tar /src/
RUN CGO_ENABLED=1 go build -mod=readonly -o /usr/local/bin/cipdip ./cmd/cipdip
COPY client.go.txt /src/cmd/corpus/main.go
RUN CGO_ENABLED=1 go build -mod=readonly -o /usr/local/bin/corpus-client ./cmd/corpus
ENTRYPOINT ["cipdip"]
