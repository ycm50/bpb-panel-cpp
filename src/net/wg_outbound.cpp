#include "net/wg_outbound.h"

#include "net/wg_socks.h"
#include "net/wg_stack.h"
#include "util/log.h"
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
    stop_wg_socks();
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
    bool up = false;
    for (int waited = 0; waited < 6000; waited += 100) {
        if (stack.ready()) {
            up = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!up) {
        // A failed handshake tears the listener down as well, otherwise the
        // SOCKS port keeps accepting and answering 0x01/0x05 -- a dead endpoint
        // that looks alive from the outside.
        stop_wg_socks();
        error = "wireguard handshake did not complete within 6s "
                "(endpoint unreachable, or the stored WARP account is no longer valid)";
        return false;
    }

    // Publish the tunnel as a local SOCKS5 endpoint.
    //
    // bindHost/socksPort have been in the settings document (and echoed back as
    // "wgOutboundSocks") since the beginning with nothing behind them, so the
    // documented way to use the outbound by hand was a connection refused while
    // the status page said ready. A listener that cannot be opened is reported
    // but does not fail the start: the inbound proxies reach the tunnel through
    // wg_outbound_ready() and are unaffected.
    const std::string bind_host =
        kv["wgOutbound"].value("bindHost", std::string("127.0.0.1"));
    const int socks_port = kv["wgOutbound"].value("socksPort", 11080);
    std::string socks_error;
    if (start_wg_socks(bind_host, socks_port, socks_error)) {
        bpb::log::info("wireguard outbound socks: %s", wg_socks_status().c_str());
    } else {
        bpb::log::warn("wireguard outbound socks not started: %s", socks_error.c_str());
    }
    return true;
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
    // Let go of the listener before the stack goes away: a SOCKS connection that
    // is mid-relay would otherwise call into a stopped lwIP and crash.
    stop_wg_socks();
    WgStack::instance().stop();
}

std::string wg_outbound_status() {
    auto& stack = WgStack::instance();
    // The socks listener is what an operator can actually reach, so its state is
    // reported even when the tunnel is down: "stack never started, port closed"
    // and "stack running, port failed to bind" are different answers, and a
    // status line that silently omits the field for the first case makes the
    // second one impossible to spot.
    const std::string socks = " socks=" + wg_socks_status();
    if (!stack.running()) return "stopped" + socks;
    return stack.describe() + socks;
}

} // namespace bpb::net
