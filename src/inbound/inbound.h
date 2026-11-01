#pragma once
#include "net/net.h"
#include "proxy/session.h"

#include <string>
#include <string_view>
#include <vector>

typedef struct ssl_st SSL;

namespace bpb::inbound {

// One inbound protocol compiled into this binary.
//
// The set is fixed at configure time (-DBPB_INBOUNDS=vless,trojan or "all"), so a
// build only carries what it ships: a VLESS-only binary does not compile, link or
// contain the other protocols' code. Everything that has to answer "which
// protocols exist here" -- the WebSocket dispatcher, the panel, the subscription
// generators and the startup log -- asks this table instead of hard-coding names.
struct Inbound {
    // Identifier used by settings, subscriptions and the CLI: "vless".
    const char* id;
    // First path segment clients connect to: "vl". null when the path depends on
    // the configuration instead of being a constant (VMess is "<uuid>-vm"), in
    // which case match() decides.
    const char* path;
    // Human label for the panel and logs: "VLESS".
    const char* label;
    // Serves one already-upgraded connection and takes ownership of the socket.
    // `path` is the full request path (query string included) so a protocol can
    // look at its own parameters; `ws_protocol` is the Sec-WebSocket-Protocol
    // request header, which carries protocol specific early data.
    void (*serve)(bpb::net::socket_t fd, SSL* ssl, std::string accept_key,
                  std::string path, std::string ws_protocol,
                  bpb::proxy::SessionConfig config);
    // Optional: decides whether a request segment belongs to this protocol when
    // the path is not a constant. Every protocol whose credential appears in the
    // path needs this (VMess: "<uuid>-vm"), the rest leave it null.
    bool (*match)(std::string_view segment, const bpb::proxy::SessionConfig& config) = nullptr;
};

// Every protocol this binary was built with, in table order.
const std::vector<const Inbound*>& all();

// Lookup by URL segment ("vl", "<uuid>-vm") or by settings id ("vless").
// nullptr when the protocol was not compiled in -- callers must treat that as
// "not available", never as "not implemented". The configuration is needed
// because a credential-derived path can only be matched against the live uuid.
const Inbound* by_path(std::string_view segment, const bpb::proxy::SessionConfig& config);
const Inbound* by_id(std::string_view id);
bool has(std::string_view id);

// "vless,trojan" in table order: what this binary can serve.
std::string id_list();
std::string path_list();

// First path segment of `path`, query string removed: "/vl?ed=2048" -> "vl".
std::string path_segment(std::string_view path);

// True when the destination must never go through the WARP outbound: loopback,
// the RFC1918 private ranges, link-local and unique-local addresses. The WARP
// netif carries those into the tunnel, where they are unroutable -- dialling
// 127.0.0.1 through it made tcp_connect() fail inside lwIP, and that failure
// path used to abort the process.
bool is_local_target(std::string_view host);

// Refuses a connection that no compiled-in protocol claims. Sends a bare 404 and
// closes, matching what the single-protocol build used to do for unknown paths.
void reject(bpb::net::socket_t fd, SSL* ssl);

} // namespace bpb::inbound
