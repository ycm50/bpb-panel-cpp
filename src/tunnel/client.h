#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace bpb::tunnel {

// End-to-end Cloudflare Tunnel client: dials the edge over TCP, speaks HTTP/2 as
// a server, registers over the capnp RPC control stream, then relays the edge's
// proxied requests to a local origin.
//
// Deliberately minimal: one control stream, no reconnect loop, no QUIC.

struct TunnelConfig {
    std::string accountTag;              // from the tunnel token
    std::string tunnelId;                // uuid text form
    std::string tunnelSecret;            // raw bytes
    std::string edgeHost = "region1.v2.argotunnel.com";
    std::uint16_t edgePort = 7844;
    std::string edgeSni = "h2.cftunnel.com";

    std::string originHost = "127.0.0.1";   // bpb panel/listener
    std::uint16_t originPort = 8080;

    int connectTimeoutMs = 15000;
    int registerTimeoutMs = 20000;
    int idlePollMs = 100;
};

struct TunnelStatus {
    bool connected = false;
    bool registered = false;
    std::string uuid;
    std::string location;
    std::string error;
    std::uint64_t requestsServed = 0;
};

class TunnelClient {
public:
    // Parses the base64 token JSON into a TunnelConfig.
    static bool parse_token(const std::string& token, TunnelConfig& out, std::string& error);

    // Runs the tunnel until stop() is called or the connection dies.
    // log receives human-readable progress lines.
    bool run(const TunnelConfig& cfg, TunnelStatus& status,
             const std::function<void(const std::string&)>& log);

    void stop() { stopping_.store(true); }
    bool stopping() const { return stopping_.load(); }

private:
    // Checked by the run loop and by the supervisor's backoff sleep; atomic so
    // stop() may be called from the HTTP thread.
    std::atomic<bool> stopping_{false};
};

} // namespace bpb::tunnel
