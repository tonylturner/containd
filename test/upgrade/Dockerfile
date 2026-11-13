# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-alpine
RUN apk add --no-cache iproute2
COPY endpoint.py /endpoint.py
CMD ["python3", "/endpoint.py"]
