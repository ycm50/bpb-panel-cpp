#pragma once
#include "net/net.h"

#include <string>
#include <vector>

typedef struct ssl_st SSL;

namespace bpb::proxy {

struct SessionConfig {
    std::string secure_path;
    std::string vl_uuid;
    std::string proxy_ip_mode;
    std::vector<std::string> proxy_ips;
};

// Takes ownership of the client socket (already upgraded to websocket).
//
// ws_protocol carries the client's Sec-WebSocket-Protocol request header. Xray
// puts the first VLESS bytes ("early data"/ed) there, base64url-encoded; the
// value must be echoed back in the 101 response and the decoded bytes replayed
// as if they had arrived in a WebSocket frame. Empty means no early data.
void run_ws_session(net::socket_t client_fd, SSL* client_ssl, std::string accept_key,
                    std::string path, std::string ws_protocol, SessionConfig config);

} // namespace bpb::proxy
