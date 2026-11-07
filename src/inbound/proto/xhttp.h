#pragma once
// XHTTP (SplitHTTP) transport.
//
// The client carries one logical byte stream over two kinds of HTTP/1.1
// requests, which is why the tunnel looks like ordinary web traffic:
//
//   GET  <prefix>/<sid>            downlink. Answered "200" + chunked and then
//                                  streamed for as long as the session lives.
//   POST <prefix>/<sid>/<seq>      uplink. One slice of the stream per request,
//                                  answered "200" and kept on the same
//                                  connection (the client pools it).
//
// Neither request carries the protocol header: the first POST body *is* the
// VLESS request (version, uuid, addons, cmd, port, target address, first
// payload bytes) and the VLESS response header travels back as the first bytes
// of the downlink body. This file therefore implements a byte stream (sessions,
// ordering, backpressure) and nothing about VLESS; the protocol runs on top of
// it in src/inbound/proto/vless_xhttp.cpp.
//
// Session lifetime: a session exists as soon as either half arrives, so POST
// before GET and GET before POST both work. It is dropped when the protocol
// finishes (finish()), when the downlink dies, or after kIdleMs without a byte
// in either direction.
#include "http/http.h"

#include "net/net.h"
#include "proxy/session.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

typedef struct ssl_st SSL;

namespace bpb::proxy::xhttp {

struct Session;
using SessionPtr = std::shared_ptr<Session>;

// Called exactly once per new session, before any uplink byte is queued. The
// protocol binding (vless_xhttp.cpp) starts its relay loop here and owns the
// session from that point; the transport keeps only the table entry.
//
// The binding installs itself with a static initialiser, so main() has nothing
// to wire: this transport refuses requests (returns false, so the panel answers
// them) unless a protocol is bound to it at startup.
using Attach = std::function<void(SessionPtr, const SessionConfig&)>;
void set_attach(Attach fn);

// Uplink read. Blocks for at most timeout_ms (sliced internally, so an idle
// session costs no CPU). Returns the byte count, 0 when the slice elapsed with
// nothing to read, and -1 when the session is over.
int read_uplink(const SessionPtr& session, char* buf, int len, int timeout_ms);

// Downlink write. Takes ownership of the bytes and applies backpressure once
// the session holds kDownQueueCap bytes: the caller blocks (without spinning)
// until the writer drained some, or returns false when the session is gone.
bool write_downlink(const SessionPtr& session, const char* data, std::size_t len);

// Ends the session gracefully: the downlink is flushed (chunked terminator) and
// the table entry is dropped, so a later request with the same id starts over.
void finish(const SessionPtr& session);

// Request entry point. Returns true when this request belonged to XHTTP and the
// socket was taken over -- whoever calls this must then forget fd/ssl, exactly
// like the websocket handler. False means "not mine, keep serving normally".
//
// "prefix" is the mounted base without a trailing slash, e.g. "/securepath/vlx".
bool takeover(net::socket_t fd, SSL* ssl, const http::Request& req,
              const SessionConfig& cfg, const std::string& prefix);

} // namespace bpb::proxy::xhttp
