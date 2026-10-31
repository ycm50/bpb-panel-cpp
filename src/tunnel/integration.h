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

// Stops the tunnel if running.
void stop();

} // namespace tunnel
} // namespace bpb
