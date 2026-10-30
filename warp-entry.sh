#!/bin/sh
# Brings up a WireGuard interface inside this container without wg-quick
# (wg-quick needs sysctl/resolvconf, which a plain container does not allow).
set -e

CONF_IN=/etc/wireguard-in/wg0.conf
WG_ONLY=/tmp/wg.conf
: > $WG_ONLY

ADDR4=""
ADDR6=""
ENDPOINT=""
DNS_LIST=""

in_peer=0
while IFS= read -r line; do
    case "$line" in
        "[Interface]") in_peer=0; echo "[Interface]" >> $WG_ONLY ;;
        "[Peer]") in_peer=1; echo "[Peer]" >> $WG_ONLY ;;
        PrivateKey*|PublicKey*|AllowedIPs*|PersistentKeepalive*)
            echo "$line" >> $WG_ONLY ;;
        Endpoint*)
            echo "$line" >> $WG_ONLY
            ENDPOINT=$(echo "$line" | sed 's/.*= *//') ;;
        DNS*)
            DNS_LIST=$(echo "$line" | sed 's/.*= *//' | tr ',' ' ') ;;
        Address*)
            vals=$(echo "$line" | sed 's/.*= *//')
            for a in $(echo "$vals" | tr ',' ' '); do
                case "$a" in
                    *:*) ADDR6="$a" ;;
                    *)   ADDR4="$a" ;;
                esac
            done ;;
        *) : ;;
    esac
done < $CONF_IN

ENDPOINT_HOST=$(echo "$ENDPOINT" | sed 's/:[0-9]*$//')
ENDPOINT_PORT=$(echo "$ENDPOINT" | sed 's/.*://')
ENDPOINT_IP=$(getent ahostsv4 "$ENDPOINT_HOST" | head -1 | awk '{print $1}')
if [ -z "$ENDPOINT_IP" ]; then
    ENDPOINT_IP=$(getent hosts "$ENDPOINT_HOST" | head -1 | awk '{print $1}')
fi
[ -z "$ENDPOINT_IP" ] && ENDPOINT_IP="$ENDPOINT_HOST"

GW=$(ip route | awk '/^default/ {print $3; exit}')

ip link add wg0 type wireguard
wg setconf wg0 $WG_ONLY
[ -n "$ADDR4" ] && ip addr add "$ADDR4" dev wg0
[ -n "$ADDR6" ] && ip -6 addr add "$ADDR6" dev wg0
ip link set mtu 1280 up dev wg0

# keep the tunnel endpoint reachable through the original gateway
if [ -n "$GW" ]; then
    ip route add "$ENDPOINT_IP"/32 via "$GW" 2>/dev/null || true
fi
ip route replace default dev wg0
ip -6 route replace default dev wg0 2>/dev/null || true

# wg-quick would push these through resolvconf; do it by hand (no resolvconf in a plain container)
if [ -n "$DNS_LIST" ]; then
    : > /etc/resolv.conf
    for d in $DNS_LIST; do
        echo "nameserver $d" >> /etc/resolv.conf
    done
    echo "resolv.conf -> $DNS_LIST"
fi

echo "warp interface up (endpoint $ENDPOINT_IP:$ENDPOINT_PORT, gw $GW)"
wg show
exec tail -f /dev/null
