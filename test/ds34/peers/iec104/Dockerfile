# SPDX-License-Identifier: Apache-2.0
# Upstream controlled stations are compiled unchanged, not copied into this tree.
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
LABEL ds34peer=true
RUN apk add --no-cache build-base linux-headers curl openjdk17-jdk python3 python3-dev cmake tcpdump tshark
WORKDIR /sources
RUN curl -fsSL https://codeload.github.com/mz-automation/lib60870/tar.gz/refs/tags/v2.4.1 -o lib60870.tar.gz \
 && echo 'd5708b9885c2c068ac9d9bae4696a624bd1d1d6645a1b1a9261c00274bc36c3a  lib60870.tar.gz' | sha256sum -c - \
 && tar -xzf lib60870.tar.gz \
 && make -C lib60870-2.4.1/lib60870-C -j2 \
 && make -C lib60870-2.4.1/lib60870-C/examples/cs104_server \
 && make -C lib60870-2.4.1/lib60870-C install INSTALL_PREFIX=/opt/lib60870
RUN curl -fsSL https://codeload.github.com/gythialy/j60870/tar.gz/dcf7e2f3767b95ae32f039cb0d4532ac5ec3e221 -o j60870.tar.gz \
 && echo '4ba53694e619ab37a89e08205d0575e20abd901cd2c1b8fcc79f278bb79f31db  j60870.tar.gz' | sha256sum -c - \
 && tar -xzf j60870.tar.gz \
 && find j60870-*/src/main/java j60870-*/cli-app/src/main/java -name '*.java' > java-sources \
 && javac --release 11 -d /opt/j60870 @java-sources
RUN curl -fsSL https://codeload.github.com/Fraunhofer-FIT-DIEN/iec104-python/tar.gz/e9a145f0370879c22fa2d12f320f44b872264241 -o c104.tar.gz \
 && echo '95a324d31430b4b4a7e69226713177e012ed84ef560ba8dfb0d4251fa675fd69  c104.tar.gz' | sha256sum -c - \
 && mkdir c104 && tar -xzf c104.tar.gz -C c104 --strip-components=1 \
 && curl -fsSL https://codeload.github.com/m-unkel/lib60870/tar.gz/97c5f856e0cf78c938f549f8f9f83f6aba8a3cd5 -o c104-lib.tar.gz \
 && echo '10586bb7fa55a49f2efde53878b9c576f75cfd8f2fba3afe2f9deb23a569b59e  c104-lib.tar.gz' | sha256sum -c - \
 && tar -xzf c104-lib.tar.gz -C c104/depends/lib60870 --strip-components=1 \
 && curl -fsSL https://codeload.github.com/Mbed-TLS/mbedtls/tar.gz/22098d41c6620ce07cf8a0134d37302355e1e5ef -o mbedtls.tar.gz \
 && echo 'fbcc09c39f16b593485141cdc7b88e63b9e656941b1df380359807831f83c9d5  mbedtls.tar.gz' | sha256sum -c - \
 && tar -xzf mbedtls.tar.gz -C c104/depends/mbedtls --strip-components=1 \
 && curl -fsSL https://codeload.github.com/pybind/pybind11/tar.gz/a2e59f0e7065404b44dfe92a28aca47ba1378dc4 -o pybind.tar.gz \
 && echo '1da0a5c38950e4f49329e9de10c59b2527840a1b963113f1c53b455971cd6aef  pybind.tar.gz' | sha256sum -c - \
 && tar -xzf pybind.tar.gz -C c104/depends/pybind11 --strip-components=1 \
 && cmake -S c104 -B c104-build -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF -DC104_VERSION_INFO=2.2.1 \
      -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=/sources/c104/c104 \
 && cmake --build c104-build --target _c104 -j2
ENV PYTHONPATH=/sources/c104
COPY master.c /sources/master.c
RUN cc -std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Werror \
    -I/opt/lib60870/include master.c /opt/lib60870/lib/liblib60870.a \
    -lpthread -o /opt/master
# Sources and upstream licences deliberately remain in the local disposable image.
COPY c104_points.py /opt/c104_points.py
