# SPDX-License-Identifier: Apache-2.0
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
ENV DEBIAN_FRONTEND=noninteractive
# Date-pinned package repository; never inherit the base image's moving mirrors.
RUN printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261001T000000Z bookworm main\n' > /etc/apt/sources.list \
    && find /etc/apt/sources.list.d -type f -exec truncate -s 0 {} \; \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends ca-certificates python3 cmake g++ make tcpdump iproute2
COPY source-lock.json fetch-inputs.py /inputs/
RUN python3 /inputs/fetch-inputs.py /inputs/source-lock.json /src \
    && cmake -S /src/opendnp3 -B /src/build -DDNP3_TESTS=OFF -DDNP3_TLS=OFF -DDNP3_EXAMPLES=OFF \
       -DCMAKE_BUILD_TYPE=Release -DFETCHCONTENT_SOURCE_DIR_ASIO=/src/asio \
       -DFETCHCONTENT_SOURCE_DIR_EXE4CPP=/src/exe4cpp -DFETCHCONTENT_SOURCE_DIR_SER4CPP=/src/ser4cpp \
    && cmake --build /src/build -j2
COPY master.cpp outstation.cpp /drivers/
RUN g++ -std=c++14 -Wall -Wextra -Werror -isystem /src/opendnp3/cpp/lib/include /drivers/master.cpp \
       -L/src/build/cpp/lib -lopendnp3 -pthread -Wl,-rpath,/src/build/cpp/lib -o /master \
    && g++ -std=c++14 -Wall -Wextra -Werror -isystem /src/opendnp3/cpp/lib/include /drivers/outstation.cpp \
       -L/src/build/cpp/lib -lopendnp3 -pthread -Wl,-rpath,/src/build/cpp/lib -o /outstation
