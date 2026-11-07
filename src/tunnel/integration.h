#pragma once
#include <string>

namespace bpb {

class Store;

namespace tunnel {

// Starts the embedded Cloudflare Tunnel client when the panel is configured
// with cfTunnel.enabled. The client registers with the edge and relays proxied
// requests to the configured local origin (the panel itself by default).
//
// Returns true when the tunnel was started (or already running). A disabled
// configuration is not an error: returns true with started == false.
bool start_from_store(Store& store, bool& started, std::string& error);

// Current status for the panel to display.
std::string status_json();

// Adopts the ingress hostname pushed by the edge into the published domain
// (Config::mainDomain) so the generated subscriptions point at a name that
// actually resolves to this connector. No-op until the edge has sent an
// ingress configuration. Must be called from the HTTP thread, which owns the
// store.
void sync_ingress_domain(Store& store);

// Undoes an earlier adoption: when the tunnel is off there is no edge in front
// of this process, so a mainDomain that still names *.trycloudflare.com points
// every generated subscription at a hostname nobody routes any more. The value
// is only rolled back when this supervisor is the one that wrote it
// (mainDomain == tunnelAdoptedDomain); a domain the operator typed by hand is
// left untouched, which is the same rule sync_ingress_domain() follows when it
// adopts one.
void release_adopted_domain(Store& store);

// Stops the tunnel if running.
void stop();

// Applies the persisted cfTunnel.enabled flag to the live connector: starts it
// when enabled, stops it when disabled. Must be called (on the HTTP thread)
// right after the panel saves its settings, otherwise "禁用" only changes the
// file while the connector keeps its edge connection alive.
void apply_store_state(Store& store);

} // namespace tunnel
} // namespace bpb
