#include "net/wg_outbound.h"

#include "net/wg_stack.h"
#include "util/util.h"

#include <chrono>
#include <cstdio>
#include <mutex>
#include <thread>

namespace bpb::net {

namespace {

// Serialises start/stop. The panel can flip the WireGuard switch while the
// tunnel thread is still unwinding its old session, and WgStack is a
// process-wide singleton: without this a stop() racing a start() could clear
// the freshly registered netif.
std::mutex g_wg_mutex;

bool pick_endpoint(const nlohmann::json& kv, std::string& endpoint) {
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object()) {
        const auto& wg = kv["wgOutbound"];
        if (wg.contains("endpoint") && wg["endpoint"].is_string()) {
            endpoint = wg["endpoint"].get<std::string>();
        }
        if (endpoint.empty()) endpoint = "162.159.192.1:2408";
        return true;
    }
    endpoint = "162.159.192.1:2408";
    return true;
}

} // namespace

bool start_wg_outbound(Store& store, std::string& error) {
    std::lock_guard<std::mutex> lk(g_wg_mutex);
    // Restart from a clean slate: the panel may have changed the account, the
    // endpoint or the reserved bytes, and reusing the running netif/socket
    // would keep serving the stale session.
    if (WgStack::instance().running()) WgStack::instance().stop();
    const auto& kv = store.kv();

    bool enabled = false;
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object()) {
        enabled = kv["wgOutbound"].value("enabled", false);
    }
    if (!enabled) {
        error = "wireguard outbound disabled";
        return false;
    }
    // Honour the same account selection the subscription generators use.
    if (kv["wgOutbound"].value("useWarpAccount", kv.value("useWarpAccount", true)) == false) {
        error = "wireguard outbound requires a WARP account";
        return false;
    }

    // Reuse the account already registered for the panel; never register here.
    const auto& warps = store.warps();
    if (!warps.is_array() || warps.empty()) {
        error = "no WARP account stored; refresh it once from the panel";
        return false;
    }
    const auto& acct = warps[0];
    std::string priv = acct.value("privateKey", std::string());
    std::string peer = acct.value("publicKey", std::string());
    std::string v6 = acct.value("warpIPv6", std::string());
    if (priv.empty() || peer.empty()) {
        error = "stored WARP account is incomplete";
        return false;
    }

    wg::PeerConfig cfg;
    cfg.private_key_b64 = priv;
    cfg.peer_public_b64 = peer;
    cfg.local_ipv6 = v6;
    cfg.local_ipv4 = "172.16.0.2";

    // WARP requires the account discriminator on every datagram. It is the
    // first three bytes of the registration client_id, stored base64-encoded.
    // Honour warpReservedBytes the same way the subscription builders do.
    const bool wantReserved = kv.value("warpReservedBytes", true);
    const std::string reservedB64 = acct.value("reserved", std::string());
    if (wantReserved && !reservedB64.empty()) {
        const std::string raw = base64_decode(reservedB64);
        if (raw.size() >= 3) {
            cfg.reserved[0] = static_cast<unsigned char>(raw[0]);
            cfg.reserved[1] = static_cast<unsigned char>(raw[1]);
            cfg.reserved[2] = static_cast<unsigned char>(raw[2]);
            cfg.has_reserved = true;
        }
    }
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object()) {
        cfg.mtu = kv["wgOutbound"].value("mtu", 1280);
        cfg.keepalive_seconds = kv["wgOutbound"].value("keepalive", 25);
    }

    // Endpoint selection follows the panel setting rather than a fixed default,
    // so a user-pinned WARP endpoint is respected.
    std::string endpoint;
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object() &&
        kv["wgOutbound"].contains("endpoint") && kv["wgOutbound"]["endpoint"].is_string() &&
        !kv["wgOutbound"]["endpoint"].get<std::string>().empty()) {
        endpoint = kv["wgOutbound"]["endpoint"].get<std::string>();
    } else {
        const auto& eps = kv.value("warpEndpoints", nlohmann::json::array());
        if (eps.is_array() && !eps.empty() && eps[0].is_string()) {
            endpoint = eps[0].get<std::string>();
        }
    }
    if (endpoint.empty()) endpoint = "162.159.192.1:2408";

    auto& stack = WgStack::instance();
    if (!stack.start(cfg, error)) return false;
    // open_udp() also starts the background driver, which sends the handshake
    // and drains the reply.
    if (!stack.open_udp(endpoint, error)) return false;

    // Report the real outcome. Returning true straight after handing the
    // initiation to the socket used to mean "enabled" was printed even when the
    // handshake never completed, so a dead tunnel looked healthy while every
    // connection quietly used a direct socket.
    for (int waited = 0; waited < 6000; waited += 100) {
        if (stack.ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    error = "wireguard handshake did not complete within 6s "
            "(endpoint unreachable, or the stored WARP account is no longer valid)";
    return false;
}

bool apply_wg_outbound(Store& store, std::string& error) {
    // Disabled: make sure a previously started stack is not left carrying
    // traffic the user just switched off.
    bool enabled = false;
    const auto& kv = store.kv();
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object()) {
        enabled = kv["wgOutbound"].value("enabled", false);
    }
    if (!enabled) {
        stop_wg_outbound();
        error = "wireguard outbound disabled";
        return false;
    }
    return start_wg_outbound(store, error);
}

bool wg_outbound_ready() {
    return WgStack::instance().running() && WgStack::instance().ready();
}

void stop_wg_outbound() {
    std::lock_guard<std::mutex> lk(g_wg_mutex);
    WgStack::instance().stop();
}

std::string wg_outbound_status() {
    auto& stack = WgStack::instance();
    if (!stack.running()) return "stopped";
    return stack.describe();
}

} // namespace bpb::net
