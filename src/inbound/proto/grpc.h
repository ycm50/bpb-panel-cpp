#pragma once
// gRPC inbound transport: HTTP/2 connection -> one byte stream per bidi stream.
//
// This is the half of the transport that Xray calls network="grpc":
//
//   * the client opens an HTTP/2 connection (h2c for security=none, or TLS over
//     the panel's own listener) and sends the connection preface;
//   * it then opens one bidi stream per proxied session, with
//     POST /<serviceName>/Tun and content-type: application/grpc;
//   * the VLESS byte stream travels inside gRPC messages, and each message body
//     is a protobuf message, not raw bytes:
//       1 compression-flag byte (always 0) + 4-byte big-endian length +
//       Hunk{bytes data = 1}  =>  0x0A + varint(len) + payload
//     (TunMulti repeats the 0x0A segment, which is the same wire format).
//     Message boundaries mean nothing to the protocol above -- a VLESS header may
//     end in the middle of a message -- which is why this layer hands out a byte
//     stream instead of framing.
//
// The HTTP/2 side lives in h2s.h; this file owns the message framing and the
// mapping stream -> session.
#include "inbound/proto/h2s.h"
#include "proxy/session.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

typedef struct ssl_st SSL;

namespace bpb::proxy::grpc {

// One gRPC stream seen as a duplex byte stream: what the protocol above relays
// over. The 5-byte message prefixes have already been stripped, so the caller
// treats it exactly like a socket.
class Stream {
public:
    virtual ~Stream() = default;

    // Reads up to len bytes. Returns >0 bytes, 0 when the slice elapsed with
    // nothing to read, -1 when the stream is finished (peer END_STREAM, RST, or
    // the whole connection died). Consumed bytes reopen the HTTP/2 window.
    virtual int read(char* buf, int len, int timeout_ms) = 0;

    // Sends one gRPC message. Blocks (in bounded slices) while the peer's
    // HTTP/2 flow-control window is closed; false means the stream is gone.
    virtual bool write(const char* data, std::size_t len) = 0;

    // Ends the stream the way gRPC expects: trailers with grpc-status 0 and
    // END_STREAM. Without them a client reports a transport error after a
    // perfectly successful transfer.
    virtual void close() = 0;

    // The :path the client asked for, e.g. "/vlg/Tun".
    virtual const std::string& path() const = 0;
};

// Serves one stream. Implemented by vless_grpc.cpp and reached through the
// inbound table (id "vless-grpc"), so a build that leaves that protocol out
// never links it.
using StreamHandler = void (*)(std::shared_ptr<Stream> stream, const SessionConfig& config);

// The settings the streams are served with. main.cpp hands them over once, next
// to the WebSocket handler; the three-argument pre_takeover() uses this copy.
void set_config(SessionConfig config);

// Entry point for http::Server::set_pre_takeover: recognises the HTTP/2
// connection preface, takes the connection over and runs the frame loop on its
// own thread. buffered holds the bytes the HTTP layer already read (preface plus
// whatever followed it). Returns false only for input that is not HTTP/2, in
// which case the connection stays with the HTTP server.
bool pre_takeover(net::socket_t fd, SSL* ssl, const std::string& buffered);
bool pre_takeover(net::socket_t fd, SSL* ssl, const std::string& buffered,
                  const SessionConfig& config);

// Implemented by vless_grpc.cpp: VLESS over one gRPC stream.
void vless_grpc_stream(std::shared_ptr<Stream> stream, const SessionConfig& config);

// The HTTP/2 limits this transport runs with (see h2s::Settings).
h2s::Settings transport_settings();

} // namespace bpb::proxy::grpc
