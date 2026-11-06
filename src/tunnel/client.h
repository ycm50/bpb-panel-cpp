#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <functional>
#include <string>
#include <vector>

namespace bpb::tunnel {

class H2Server;

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
    //
    // It is also invoked after a served request is accounted for, but only at
    // most once per publishIntervalMs: the panel polls status on every render,
    // and republishing per request would mean taking the tunnel's status mutex
    // once per HTTP request just to bump a counter nobody reads that often.
    bool run(const TunnelConfig& cfg, TunnelStatus& status,
             const std::function<void(const std::string&)>& log,
             const std::function<void(const TunnelStatus&)>& on_status = {});

    // Ask the relay to stop. Wakes the connection immediately (shutdown(2) on
    // the edge socket) so run() returns within one poll slice instead of
    // sitting in a 100 ms poll -- or, worse, in a minutes-long blocking
    // connect() to a black-holed edge.
    void stop() {
        stopping_.store(true);
        abort_connection();
    }
    bool stopping() const { return stopping_.load(); }

    // Requests served so far. The live counter, not a snapshot: run() publishes
    // its status into the integration layer only at connect/register/ingress
    // moments, and the panel would otherwise show the value from the last of
    // those while the tunnel kept serving.
    std::uint64_t requests_served() const { return requests_served_.load(); }

private:
    // shutdown(2)s the live edge socket, if any. Safe to call from another
    // thread: the pointer is published under mutex_ and cleared before the
    // server is destroyed.
    void abort_connection();

    // Checked by the run loop and by the supervisor's backoff sleep; atomic so
    // stop() may be called from the HTTP thread.
    std::atomic<bool> stopping_{false};
    // Incremented by the relay for every request whose origin response was
    // relayed. Atomic because the panel thread reads it while run() writes it.
    std::atomic<std::uint64_t> requests_served_{0};
    // Guards live_ only; never held across a blocking operation.
    mutable std::mutex mutex_;
    H2Server* live_ = nullptr;
};

} // namespace bpb::tunnel
