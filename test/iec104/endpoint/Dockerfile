# containd IEC 60870-5-104 truth-harness endpoint image (GPLv3).
#
# This image carries one program, iec104ep, which links lib60870-C
# (MZ Automation, GPLv3-or-commercial). It is a harness-only image: it is
# never linked into containd (Apache-2.0, own Go parser). The
# endpoints talk to containd only over TCP/2404. The corresponding source
# for every GPLv3 binary — the pinned lib60870 tarball and iec104ep.c —
# ships under /usr/share/src, with the GPLv3 licence under
# /usr/share/licenses/iec104.
#
# Pin the base image by digest and lib60870 by tag + SHA256 for a
# reproducible, offline-verifiable build. Multi-arch capable: every stage
# builds from source, so buildx can target linux/amd64 and linux/arm64.

ARG ALPINE_DIGEST=sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
FROM alpine:3.21@${ALPINE_DIGEST} AS build

ARG LIB60870_VERSION=2.4.1
ARG LIB60870_SHA256=d5708b9885c2c068ac9d9bae4696a624bd1d1d6645a1b1a9261c00274bc36c3a

RUN apk add --no-cache build-base curl linux-headers

WORKDIR /src
RUN curl -fsSL -o lib60870.tar.gz \
        "https://github.com/mz-automation/lib60870/archive/refs/tags/v${LIB60870_VERSION}.tar.gz" \
 && echo "${LIB60870_SHA256}  lib60870.tar.gz" | sha256sum -c - \
 && mkdir lib60870 \
 && tar -xzf lib60870.tar.gz -C lib60870 --strip-components=1

RUN make -C lib60870/lib60870-C -j"$(nproc)" \
 && make -C lib60870/lib60870-C install INSTALL_PREFIX=/opt/lib60870

COPY iec104ep.c /src/iec104ep.c
RUN mkdir -p /out && cc -std=gnu11 -O2 -Wall -Wextra -Werror -I/opt/lib60870/include \
       -o /out/iec104ep /src/iec104ep.c \
       /opt/lib60870/lib/liblib60870.a -lpthread

FROM alpine:3.21@${ALPINE_DIGEST}
RUN apk add --no-cache iproute2 iptables
COPY --from=build /out/iec104ep /usr/local/bin/iec104ep
COPY LICENSE /usr/share/licenses/iec104/LICENSE
COPY --from=build /src/lib60870.tar.gz /usr/share/src/lib60870.tar.gz
COPY iec104ep.c /usr/share/src/iec104ep.c
EXPOSE 2404
ENTRYPOINT ["iec104ep"]
CMD ["rtu"]
