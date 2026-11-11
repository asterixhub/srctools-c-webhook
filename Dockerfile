# syntax=docker/dockerfile:1
FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev make curl tar
WORKDIR /src
RUN curl -fsSL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-3.6.0.tar.gz -o m.tar.gz \
 && tar -xzf m.tar.gz && mv mbedtls-mbedtls-3.6.0 mbedtls
COPY mbedtls_config.h /src/mbedtls/include/mbedtls/mbedtls_config.h
COPY src/main.c /src/main.c
RUN cd mbedtls && make -j4 lib CFLAGS="-O2" \
 && cd /src && gcc -O2 -s -static -I mbedtls/include -o /worker main.c \
    mbedtls/library/libmbedtls.a mbedtls/library/libmbedx509.a mbedtls/library/libmbedcrypto.a \
 && ls -l /worker

FROM scratch
COPY ca-bundle.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /worker /worker
ENV RAILWAY_VOLUME_MOUNT_PATH=/data
ENTRYPOINT ["/worker"]
