# One-time build toolchain image (needs network once).
# Switch the mirror if dl-cdn.alpinelinux.org is slow:
#   docker build --build-arg ALPINE_MIRROR=mirrors.aliyun.com -f native/buildenv.Dockerfile -t bpb-buildenv:base .
FROM alpine:3.22

ARG ALPINE_MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s#dl-cdn.alpinelinux.org#${ALPINE_MIRROR}#g" /etc/apk/repositories \
 && apk add --no-cache g++ musl-dev openssl-dev openssl-libs-static zlib-dev zlib-static \
        ca-certificates
