# syntax=docker/dockerfile:1
FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev mbedtls-dev mbedtls-static
WORKDIR /src
COPY src/main.c /src/main.c
RUN gcc -O2 -s -static -o /worker main.c -lmbedtls -lmbedx509 -lmbedcrypto

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /worker /worker
ENV RAILWAY_VOLUME_MOUNT_PATH=/data
ENTRYPOINT ["/worker"]
