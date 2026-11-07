#pragma once
// Minimal HTTP/2 *server* (RFC 7540) for inbound transports.
//
// Why this exists: the gRPC transport (grpc.h) is an HTTP/2 transport -- every
// real Xray / sing-box / v2rayN gRPC client opens a TLS- or h2c-connection,
// sends the HTTP/2 connection preface and then speaks HPACK-compressed request
// headers on multiplexed streams. There is no "just read the raw bytes"
// shortcut, so a small, self-contained h2 endpoint has to live here.
//
// Implemented on purpose:
//   frames   SETTINGS (+ACK), HEADERS (+CONTINUATION), DATA, WINDOW_UPDATE,
//            PING, RST_STREAM, GOAWAY, PRIORITY (parsed and ignored)
//   HPACK    complete decoder: static table, dynamic table with the size bound
//            announced in SETTINGS, Huffman literals, table-size updates;
//            minimal encoder: :status, content-type, trailers
//   flow     our receive windows (per stream and per connection) reopened in
//            batches as the session consumes bytes, and the peer's send windows
//            honoured before every DATA frame -- without both, a gRPC stream
//            stalls at 64 KiB or gets reset by the client
//   limits   MAX_CONCURRENT_STREAMS=64, 4 MiB of unconsumed bytes per
//            connection, a connection with no frame for 60 s is reclaimed
//
// Threading model: run() is the single connection thread and the only reader --
// it also owns fd/ssl and closes both before returning. Any number of session
// threads (one per gRPC stream, in practice) may call write_data(), consume(),
// rst_stream() and write_headers() concurrently; they are serialised inside.
#include "net/net.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

typedef struct ssl_st SSL;

namespace bpb::proxy::h2s {

// One decoded header field. Names arrive lower-case, exactly as HPACK has them.
using Header = std::pair<std::string, std::string>;
using Headers = std::vector<Header>;

// Tunables. Every value here was picked from a measurement on the target VPS
// (469 MB RAM, one core), so they are named instead of being sprinkled through
// the code:
//   stream_window        256 KiB per stream: enough in flight to keep a single
//                        gRPC stream busy for a whole RTT without pinning more
//                        memory than a slow client can usefully absorb.
//   connection_window    2 MiB, reopened in 1 MiB batches. The protocol default
//                        of 64 KiB caps a connection at one window per RTT,
//                        which on a 200 ms path is 300 KiB/s.
//   max_buffered         4 MiB of bytes handed to the session but not consumed
//                        yet: the hard ceiling that keeps a stalled session from
//                        growing the process.
struct Settings {
    std::uint32_t max_concurrent_streams = 64;
    std::uint32_t stream_window = 256 * 1024;
    std::uint32_t connection_window = 2 * 1024 * 1024;
    std::size_t stream_credit_batch = 64 * 1024;
    std::size_t connection_credit_batch = 1024 * 1024;
    std::size_t max_buffered = 4 * 1024 * 1024;
    int idle_ms = 60000;
};

// Callbacks. All of them run on the connection thread, so a handler may block
// for as long as the session it starts needs -- but the connection's own
// progress stops meanwhile, so a handler that starts a session must do so in
// its own thread (grpc.cpp does).
struct Handlers {
    // A complete request header block (one HEADERS plus its CONTINUATIONs).
    // Called once per request stream; a later block on the same stream is
    // treated as trailers and reported through on_end_stream instead.
    std::function<void(std::uint32_t stream, const Headers& headers)> on_headers;
    // Request body bytes. The length may be anything; the peer's frame
    // boundaries are not preserved.
    std::function<void(std::uint32_t stream, const char* data, std::size_t len)> on_data;
    // The peer finished its half of the stream (END_STREAM on DATA or trailers).
    std::function<void(std::uint32_t stream)> on_end_stream;
    // The peer aborted the stream (RST_STREAM). Nothing may be written on it
    // afterwards; write_data() returns false for it from now on.
    std::function<void(std::uint32_t stream)> on_reset_stream;
};

class Server {
public:
    virtual ~Server() = default;

    // Connection thread body: sends our SETTINGS, then services frames until the
    // connection dies or idles out. Owns fd and ssl, closes both on return.
    virtual void run() = 0;

    // Queues the payload as DATA frames. Blocks while the peer's flow-control
    // window is closed (in short slices, so a dying connection is noticed);
    // returns false when the stream or the connection is gone, and the caller
    // must treat the stream as finished.
    virtual bool write_data(std::uint32_t stream, const char* data, std::size_t len) = 0;

    // Sends a HEADERS frame. The fields are complete, :status included, and the
    // names must be lower-case. end_stream marks the end of our half.
    virtual bool write_headers(std::uint32_t stream, const Headers& headers, bool end_stream) = 0;

    // Reports that n bytes previously handed to on_data for this stream have
    // been consumed by the session. That is what reopens the receive window and
    // what lets the buffering ceiling release the reader.
    virtual void consume(std::uint32_t stream, std::size_t bytes) = 0;

    // Aborts a stream (RST_STREAM). Used when the session behind it failed.
    virtual void rst_stream(std::uint32_t stream, std::uint32_t code) = 0;

    // Releases the per-stream bookkeeping once the session behind the stream is
    // over. The caller has already sent END_STREAM (trailers) or RST_STREAM;
    // this only frees the slot, so a connection that has served hundreds of
    // streams in turn does not run into MAX_CONCURRENT_STREAMS.
    virtual void close_stream(std::uint32_t stream) = 0;

    // False as soon as the connection is unusable, so session threads stop
    // waiting for a write that will never succeed.
    virtual bool alive() const = 0;
};

// Takes ownership of fd and ssl. The buffered string holds the bytes the HTTP
// layer already read: at least the 24-byte connection preface, possibly whole
// frames after it (Xray sends preface+SETTINGS+WINDOW_UPDATE in one segment).
std::shared_ptr<Server> create(net::socket_t fd, SSL* ssl, std::string buffered, Handlers handlers,
                               Settings settings = Settings{});

// RST_STREAM / GOAWAY error codes used by this layer (RFC 7540 s7).
inline constexpr std::uint32_t kNoError = 0;
inline constexpr std::uint32_t kProtocolError = 1;
inline constexpr std::uint32_t kInternalError = 2;
inline constexpr std::uint32_t kFlowControlError = 3;
inline constexpr std::uint32_t kFrameSizeError = 6;
inline constexpr std::uint32_t kRefusedStream = 7;
inline constexpr std::uint32_t kCancel = 8;
inline constexpr std::uint32_t kEnhanceYourCalm = 11;

} // namespace bpb::proxy::h2s
