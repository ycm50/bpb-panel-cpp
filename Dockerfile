# Build (deployment image):
#   docker build -t bpb-native:1.0.0 .
#   # optional local speed-up: reuse a pre-built toolchain image
#   docker build --build-arg BASE=bpb-buildenv:base -t bpb-native:1.0.0 .
# Run:
#   docker run -d -p 8080:8080 -v bpb-data:/data bpb-native:1.0.0
ARG BASE=alpine:3.22
FROM ${BASE} AS build

# The toolchain is only installed when the base image does not already carry it,
# so the same file works for both the stock alpine base and bpb-buildenv:base.
RUN command -v g++ >/dev/null 2>&1 || apk add --no-cache \
        g++ musl-dev openssl-dev openssl-libs-static zlib-dev zlib-static ca-certificates

WORKDIR /src
COPY . /src
RUN g++ -O2 -std=c++20 -static -ffunction-sections -fdata-sections \
        -Isrc -Ithird_party \
        src/*.cpp src/*/*.cpp third_party/qrcodegen.cpp \
        -o /bpb -lssl -lcrypto -lz -lpthread \
 && strip /bpb

FROM scratch

COPY --from=build /bpb /bpb
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/bpb", "--host", "0.0.0.0", "--port", "8080", "--data", "/data"]
