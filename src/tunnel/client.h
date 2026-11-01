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
    // Wait used when nothing at all is happening (no stream open).
    int idlePollMs = 100;
    // Wait used while a proxied stream is open. srv->poll() only watches the
    // edge socket, so origin bytes are noticed at this granularity; anything
    // near idlePollMs throttles downloads to 16 KB per tick and adds that much
    // latency to every round trip. A couple of milliseconds keeps the pipe
    // full without spinning at poll(0).
    int activePollMs = 2;
};

struct TunnelStatus {
    bool connected = false;
    bool registered = false;
    std::string uuid;
    std::string location;
    std::string error;
    std::uint64_t requestsServed = 0;
    // Public hostnames the edge put in this tunnel's ingress configuration.
    // For a named tunnel this is the ONLY way the connector learns its own
    // hostname: the token has a/t/s only, and the REST API that would answer it
    // (cfd_tunnel/<id>/configurations) requires a separate account API token
    // which the panel does not have and must not ask the user for.
    std::vector<std::string> hostnames;
};

class TunnelClient {
public:
    // Parses the base64 token JSON into a TunnelConfig.
    static bool parse_token(const std::string& token, TunnelConfig& out, std::string& error);

    // Runs the tunnel until stop() is called or the connection dies.
    // log receives human-readable progress lines. on_status, when set, is
    // invoked every time the status actually changes (connected, registered,
    // ingress hostnames) so the panel reports the live state instead of the
    // snapshot taken after the first connection attempt.
    bool run(const TunnelConfig& cfg, TunnelStatus& status,
             const std::function<void(const std::string&)>& log,
             const std::function<void(const TunnelStatus&)>& on_status = {});

    void stop() { stopping_.store(true); }
    bool stopping() const { return stopping_.load(); }

private:
    // Checked by the run loop and by the supervisor's backoff sleep; atomic so
    // stop() may be called from the HTTP thread.
    std::atomic<bool> stopping_{false};
};

} // namespace bpb::tunnel
