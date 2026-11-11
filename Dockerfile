# syntax=docker/dockerfile:1
FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev make curl tar
WORKDIR /src
RUN curl -fsSL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-3.6.0.tar.gz -o m.tar.gz \
 && tar -xzf m.tar.gz && mv mbedtls-mbedtls-3.6.0 mbedtls
COPY mbedtls_config.h /src/mbedtls_config.h
COPY src/main.c /src/main.c
RUN cd mbedtls && make -j4 lib CFLAGS="-O2 -I/src -DMBEDTLS_CONFIG_FILE='\"/src/mbedtls_config.h\"'" \
 && cd /src \
 && gcc -O2 -s -static -I/src -I/src/mbedtls/include -DMBEDTLS_CONFIG_FILE='"/src/mbedtls_config.h"' \
    -o /worker main.c mbedtls/library/libmbedcrypto.a mbedtls/library/libmbedx509.a mbedtls/library/libmbedtls.a

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /worker /worker
ENV RAILWAY_VOLUME_MOUNT_PATH=/data
ENTRYPOINT ["/worker"]
