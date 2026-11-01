#pragma once
#include "wg/device.h"

#include <cstdint>
#include <memory>
#include <string>

namespace bpb::net {

class WgConnection;

// Owns the userspace TCP/IP stack (lwIP) plus the WireGuard device that
// carries its packets. All lwIP access is serialised behind one mutex and
// driven by pump(); callers block by repeatedly pumping with a short sleep.
class WgStack {
public:
    static WgStack& instance();

    bool start(const wg::PeerConfig& cfg, std::string& error);
    void stop();
    bool running() const;
    bool ready();

    // Opens the UDP socket towards the WireGuard endpoint ("host:port").
    bool open_udp(const std::string& endpoint, std::string& error);

    // Sends a handshake initiation when no valid session exists.
    bool ensure_tunnel(std::string& error);

    // Resolves host and opens a TCP connection through the tunnel.
    std::unique_ptr<WgConnection> connect(const std::string& host, int port, int timeout_ms,
                                          std::string& error);

    // Drains the UDP socket into the WireGuard device and runs lwIP timers.
    void pump();

    // The handshake response only ever arrives on the UDP socket, so the stack
    // must be driven even when no connect() is in flight. Without this,
    // has_session() never becomes true and every connection silently falls back
    // to a direct socket. start_driver() runs pump()+ensure_tunnel() in the
    // background; stop_driver() joins it.
    void start_driver();
    void stop_driver();

    unsigned long long rx_bytes();
    unsigned long long tx_bytes();
    std::string describe();

    // Internal hook used by the connection callbacks.
    struct Impl;
    Impl& impl() { return *impl_; }

private:
    WgStack();
    ~WgStack();
    std::unique_ptr<Impl> impl_;
};

// A TCP connection carried inside the WireGuard tunnel.
class WgConnection {
public:
    explicit WgConnection(void* pcb);
    ~WgConnection();
    WgConnection(const WgConnection&) = delete;
    WgConnection& operator=(const WgConnection&) = delete;

    // Returns bytes read, 0 on timeout, -1 when the connection is gone.
    int read(char* buf, int len, int timeout_ms);
    int write(const char* buf, int len);
    void close();
    bool valid() const;

    struct State;
    State& state() { return *state_; }

private:
    std::unique_ptr<State> state_;
};

} // namespace bpb::net
