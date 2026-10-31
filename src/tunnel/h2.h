#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace bpb::tunnel {

// Debug tracing for the h2 frame layer; enabled by the BPB_TUNNEL_TRACE
// environment variable so production stays quiet.
bool h2_trace_enabled();
void h2_trace(const char* fmt, ...);

// Minimal HTTP/2 *server* over a dialed TLS connection, for the Cloudflare
// tunnel transport.
//
// Verified against the live edge:
//   * TCP + TLS: WE are the client (we dial region1.v2.argotunnel.com:7844 with
//     SNI h2.cftunnel.com). ALPN is empty and must not be required.
//   * HTTP/2: WE are the server. After the TLS handshake the edge sends
//     "PRI * HTTP/2.0" and its SETTINGS, then opens POST streams towards us.
// This mirrors cloudflared, which does tls.Client(...) + http2.Server.ServeConn.

// Decodes a complete HTTP/2 header block (static + dynamic table, huffman
// literals) into name/value pairs. Exposed so diagnostics and test harnesses
// can inspect what the edge sends without duplicating the HPACK code.
void decode_hpack(const std::uint8_t* block, std::size_t len,
                  std::map<std::string, std::string>& out);

class H2Server {
public:
    struct Request {
        std::uint32_t streamId = 0;
        std::string method;
        std::string path;
        std::map<std::string, std::string> headers;  // lower-case names
    };

    struct Callbacks {
        std::function<void(const Request&)> on_request;
        std::function<void(std::uint32_t streamId, const std::uint8_t* data, std::size_t len)> on_data;
        std::function<void(std::uint32_t streamId)> on_end;
        // The edge aborted the stream (RST_STREAM). Distinct from on_end: the
        // peer is gone, so nothing more may be written on it.
        std::function<void(std::uint32_t streamId)> on_reset;
        std::function<void(const std::string&)> on_error;
    };

    static H2Server* create(const Callbacks& cb);
    virtual ~H2Server() = default;

    // Dials the edge and performs the TLS client handshake.
    virtual bool connect(const std::string& host, std::uint16_t port, const std::string& sni,
                         int timeout_ms, std::string& error) = 0;

    // Consumes the edge's HTTP/2 preface + SETTINGS and replies with our own,
    // switching the connection into server mode.
    virtual bool startHttp2(int timeout_ms, std::string& error) = 0;

    // Services frames. Returns false when the peer closed or a fatal error hit.
    virtual bool poll(int timeout_ms) = 0;

    virtual bool write_headers(std::uint32_t streamId, const std::string& status,
                               const std::vector<std::pair<std::string, std::string>>& extra,
                               bool endStream) = 0;
    // Streams DATA while honouring the peer's HTTP/2 flow-control window. Blocks
    // (polling) until the whole buffer is accepted, so callers may treat a true
    // return as "everything handed to the edge". Partial writes are tracked
    // internally; on failure the caller must consider the stream dead.
    virtual bool write_data(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                            bool endStream) = 0;

    // Non-waiting variant: writes only what the peer's flow-control window
    // allows right now and returns the number of bytes accepted (0 when the
    // window is closed). The caller must retain the remainder and retry after
    // servicing the read side. cloudflared gets this for free from separate
    // goroutines; a single-threaded relay must never block here, or the origin
    // stops being drained while we wait for credit.
    virtual std::size_t write_data_some(std::uint32_t streamId, const std::uint8_t* data,
                                        std::size_t len, bool endStream) = 0;

    // Resets a stream. Used when the local origin is gone, so the edge tears
    // the eyeball connection down instead of waiting for a body that will
    // never arrive.
    virtual bool write_rst_stream(std::uint32_t streamId, std::uint32_t errorCode) = 0;

    virtual void close() = 0;
};

inline constexpr const char* kUpgradeHeader = "cf-cloudflared-proxy-connection-upgrade";
inline constexpr const char* kUpgradeControlStream = "control-stream";
inline constexpr const char* kUpgradeConfiguration = "update-configuration";

} // namespace bpb::tunnel
