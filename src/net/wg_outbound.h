#pragma once
#include "settings/store.h"

#include <string>

namespace bpb::net {

// Starts the WARP outbound from the stored settings.
// Returns false (and leaves it stopped) when the feature is disabled or unusable;
// the reason is written to *error.
bool start_wg_outbound(Store& store, std::string& error);

// Applies the current settings to the running outbound: starts it when enabled,
// stops it when disabled, and restarts it when it is already up so a changed
// account/endpoint takes effect without restarting the process. Returns the
// resulting readiness. Safe to call from the HTTP thread.
bool apply_wg_outbound(Store& store, std::string& error);

// Tears the outbound down (used when the feature is turned off).
void stop_wg_outbound();

// True when a session is established and can carry traffic.
bool wg_outbound_ready();

// Human readable status for the panel / logs.
std::string wg_outbound_status();

} // namespace bpb::net
