// Windows stub for the built-in Cloudflare Tunnel client.
//
// The real implementation under src/tunnel/ is POSIX-specific: it drives
// poll(2), uses <arpa/inet.h>, <sys/socket.h> and <netinet/tcp.h>, and treats
// sockets as plain ints. MSYS2/MinGW has none of those, so instead of carrying
// a second protocol backend we compile this stub for Windows builds.
//
// Behaviour: the tunnel is always reported as unavailable and the panel keeps
// working. Everything else (HTTP server, VLESS over WebSocket, subscriptions,
// WARP userspace outbound) is unaffected.

#include "tunnel/integration.h"

#include "settings/store.h"

#include <cstdio>

namespace bpb::tunnel {

bool start_from_store(Store& store, bool& started, std::string& error) {
    started = false;
    const nlohmann::json kv = store.merged();
    if (!kv.contains("cfTunnel") || !kv["cfTunnel"].is_object()) return true;
    const auto& t = kv["cfTunnel"];
    if (!t.value("enabled", false)) return true;

    // Configured but unsupported on this platform: say so instead of silently
    // pretending the tunnel is running.
    error = "the built-in Cloudflare Tunnel client is not available on Windows builds";
    std::fprintf(stderr, "[cf-tunnel] %s\n", error.c_str());
    return false;
}

std::string status_json() {
    return "{\"running\":false,\"connected\":false,\"registered\":false,\"uuid\":\"\","
           "\"location\":\"\",\"requests\":0,\"quick\":false,"
           "\"hostname\":\"\",\"url\":\"\",\"hostnames\":[],\"mainDomain\":\"\","
           "\"error\":\"not available on this platform\"}";
}

void sync_ingress_domain(Store&) {
    // No tunnel on this platform, so there is no ingress configuration to
    // adopt and the published domain stays whatever the user configured.
}

void stop() {}

} // namespace bpb::tunnel
