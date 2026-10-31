# SPDX-License-Identifier: Apache-2.0
FROM alpine:3.21
RUN apk add --no-cache tcpdump
ENTRYPOINT ["tcpdump"]
