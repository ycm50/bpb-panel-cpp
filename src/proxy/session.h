#pragma once
#include "net/net.h"

#include <string>
#include <vector>

typedef struct ssl_st SSL;

namespace bpb::proxy {

struct SessionConfig {
    std::string secure_path;
    std::string vl_uuid;
    std::string tr_pass;
    std::string proxy_ip_mode;
    std::vector<std::string> proxy_ips;
};

// Takes ownership of the client socket (already upgraded to websocket).
void run_ws_session(net::socket_t client_fd, SSL* client_ssl, std::string accept_key,
                    std::string path, SessionConfig config);

} // namespace bpb::proxy
