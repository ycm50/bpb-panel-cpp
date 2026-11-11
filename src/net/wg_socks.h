#pragma once
#include <string>

namespace bpb::net {

// Exposes the in-process WireGuard tunnel as a local SOCKS5 endpoint.
//
// The panel has always carried wgOutbound.bindHost / wgOutbound.socksPort and
// reported the pair as "wgOutboundSocks", but nothing ever listened on it: the
// stack was only reachable from the inbound proxies through
// wg_outbound_ready(). `curl --socks5 127.0.0.1:11080` got ECONNREFUSED while
// the status page said "ready", which is the worst kind of half-implemented
// feature -- it looks configured and cannot be used.
//
// Only CONNECT is implemented. BIND and UDP ASSOCIATE are refused: the tunnel
// carries TCP through lwIP, so there is nothing to bind and no UDP path.
bool start_wg_socks(const std::string& bind_host, int port, std::string& error);

// Stops the listener and every relay it is carrying. Safe to call when it was
// never started.
void stop_wg_socks();

bool wg_socks_running();

// "127.0.0.1:11080 (3 active)" for the log/status line.
std::string wg_socks_status();

} // namespace bpb::net
