#pragma once
#include "net/net.h"

#include <string>
#include <vector>

typedef struct ssl_st SSL;

namespace bpb::proxy {

// Settings an inbound protocol needs in order to serve a connection. Kept
// protocol agnostic on purpose: whatever a protocol does with these, the
// dispatcher only has to hand them over.
struct SessionConfig {
    std::string secure_path;
    std::string vl_uuid;
    std::string proxy_ip_mode;
    std::vector<std::string> proxy_ips;
};

// Serving a WebSocket connection is protocol specific and lives in
// src/inbound/proto/<protocol>_ws.cpp; see src/inbound/inbound.h for the table
// that decides which ones this binary was built with.

} // namespace bpb::proxy
