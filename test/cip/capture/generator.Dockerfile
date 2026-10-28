# SPDX-License-Identifier: Apache-2.0
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
ENV DEBIAN_FRONTEND=noninteractive
RUN printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261001T000000Z bookworm main\n' > /etc/apt/sources.list \
    && find /etc/apt/sources.list.d -type f -exec truncate -s 0 {} \; \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends ca-certificates python3 cmake g++ make libcap-dev tcpdump iproute2
COPY source-lock.json fetch-inputs.py /inputs/
RUN python3 /inputs/fetch-inputs.py /inputs/source-lock.json /src \
    && cmake -S /src/opener/source -B /src/opener-build -DOpENer_PLATFORM=POSIX -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /src/opener-build -j2 \
    && cmake -S /src/eipscanner -B /src/scanner-build -DCMAKE_BUILD_TYPE=Release -DENABLE_VENDOR_SRC=OFF \
    && cmake --build /src/scanner-build -j2
COPY scanner.cpp /drivers/scanner.cpp
RUN g++ -std=c++20 -Wall -Wextra -Werror -isystem /src/eipscanner/src /drivers/scanner.cpp \
    -L/src/scanner-build/src -lEIPScanner -Wl,-rpath,/src/scanner-build/src -o /scanner
