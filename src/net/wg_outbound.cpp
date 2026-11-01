#include "net/wg_outbound.h"

#include "net/warp_proc.h"

namespace bpb::net {

// The WARP outbound used to be an in-tree userspace WireGuard stack. Account
// management (register once, persist, rotate, refresh) and the netstack turned
// out to be the fragile half, and duplicate registrations are rate limited by
// Cloudflare, so that responsibility now lives in the supervised external
// process "warp-rust" (third_party/cf-warp-rust). bpb only:
//   * renders its config,
//   * keeps the process alive,
//   * dials target hosts through the SOCKS5 port it publishes.
// See net/warp_proc.h for the contract.

bool start_wg_outbound(Store& store, std::string& error) {
    // Kept for the callers' sake: "disabled" is a normal state, not a failure,
    // and main.cpp distinguishes the two by this exact string.
    return warp_proc_start(store, error);
}

// Hot apply: the session lives in a separate process which renders/reads its
// config once at startup, so a settings change means stopping the child and
// starting it again. warp_proc_stop() is safe when nothing is running, and the
// "disabled" reason matches start_wg_outbound so callers only special-case one
// string.
bool apply_wg_outbound(Store& store, std::string& error) {
    const nlohmann::json kv = store.merged();
    bool enabled = false;
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object()) {
        enabled = kv["wgOutbound"].value("enabled", false);
    }
    warp_proc_stop();
    if (!enabled) {
        error = "wireguard outbound disabled";
        return false;
    }
    return warp_proc_start(store, error);
}

void stop_wg_outbound() { warp_proc_stop(); }

bool wg_outbound_ready() { return warp_proc_ready(); }

std::string wg_outbound_status() { return warp_proc_status(); }

} // namespace bpb::net
