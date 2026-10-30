# Sidecar that terminates Cloudflare WARP for the bpb container.
# wg0.conf comes from:  bpb --export-warp ./warp/wg0.conf --data ./data --assets ./assets
FROM alpine:3.22

ARG ALPINE_MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s#dl-cdn.alpinelinux.org#${ALPINE_MIRROR}#g" /etc/apk/repositories \
 && apk add --no-cache wireguard-tools iproute2 iptables ca-certificates

COPY warp-entry.sh /warp-entry.sh
RUN chmod +x /warp-entry.sh

ENTRYPOINT ["/warp-entry.sh"]
