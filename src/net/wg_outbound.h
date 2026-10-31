#pragma once
#include "settings/store.h"

#include <string>

namespace bpb::net {

// Starts the userspace WireGuard outbound from the stored settings.
// Returns false (and leaves the stack stopped) when the feature is disabled or
// no usable WARP account is present; the reason is written to *error.
bool start_wg_outbound(Store& store, std::string& error);

// True when a session is established and can carry traffic.
bool wg_outbound_ready();

// Human readable status for the panel / logs.
std::string wg_outbound_status();

} // namespace bpb::net
