#include "net/wg_socks.h"

#include "net/net.h"
#include "net/wg_outbound.h"
#include "net/wg_stack.h"
#include "util/log.h"
#include "util/thread.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bpb::net {

namespace {

// Upper bound on data buffered from the tunnel towards the client. A SOCKS
// client that stops reading must not make the panel allocate without limit: the
// relay simply stops pulling from WgConnection until the client drains, and TCP
// flow control inside the tunnel then throttles the origin.
constexpr std::size_t kMaxPending = 256 * 1024;

constexpr unsigned char kSocksVersion = 5;
constexpr unsigned char kAuthNone = 0x00;
constexpr unsigned char kCmdConnect = 0x01;
constexpr unsigned char kAtypIpv4 = 0x01;
constexpr unsigned char kAtypDomain = 0x03;
constexpr unsigned char kAtypIpv6 = 0x04;

std::mutex g_mutex;
socket_t g_listener = kInvalid;
std::thread g_accept_thread;
std::atomic<bool> g_running{false};
std::atomic<int> g_active{0};
// Set while the listener is being torn down. Relays are detached threads that
// call into WgStack, so they must be told to leave BEFORE the stack goes away --
// a relay touching a stopped lwIP is a use-after-free, not a slow exit.
std::atomic<bool> g_draining{false};
std::string g_bind_desc;

// Reads exactly `len` bytes, giving up after `timeout_ms` in total.
bool read_full(socket_t fd, void* dst, std::size_t len, int timeout_ms) {
    auto* p = static_cast<char*>(dst);
    std::size_t got = 0;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (got < len) {
        const int n = static_cast<int>(::recv(fd, p + got, static_cast<int>(len - got), 0));
        if (n > 0) {
            got += static_cast<std::size_t>(n);
            continue;
        }
        if (n == 0) return false;  // peer closed mid-handshake
        const int err = last_error();
        if (!would_block(err)) return false;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        PollFd pfd{fd, kRead, 0};
        poll_fds(&pfd, 1, 50);
    }
    return true;
}

bool write_full(socket_t fd, const void* data, std::size_t len) {
    const char* p = static_cast<const char*>(data);
    std::size_t sent = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (sent < len) {
        const int n = static_cast<int>(::send(fd, p + sent, static_cast<int>(len - sent), 0));
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        const int err = last_error();
        if (!would_block(err)) return false;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        PollFd pfd{fd, kWrite, 0};
        poll_fds(&pfd, 1, 50);
    }
    return true;
}

// SOCKS5 reply. The bound address is always reported as 0.0.0.0:0 -- the tunnel
// has no listener of its own to name, and every client treats the field as
// informational after CONNECT.
void send_reply(socket_t fd, unsigned char code) {
    unsigned char reply[10] = {kSocksVersion, code, 0x00, kAtypIpv4, 0, 0, 0, 0, 0, 0};
    write_full(fd, reply, sizeof(reply));
}

// RFC 1929 username/password negotiation, answered with "no acceptable methods".
// The listener is bound to loopback by default; when an operator points it at a
// public interface an unauthenticated CONNECT is exactly the open-relay problem,
// so refusing to negotiate a login is the honest answer rather than pretending.
bool negotiate(socket_t fd) {
    unsigned char head[2];
    if (!read_full(fd, head, 2, 10000)) return false;
    if (head[0] != kSocksVersion) return false;
    const std::size_t nmethods = head[1];
    if (nmethods == 0 || nmethods > 32) return false;
    std::vector<unsigned char> methods(nmethods);
    if (!read_full(fd, methods.data(), nmethods, 10000)) return false;
    bool ok = false;
    for (unsigned char m : methods) {
        if (m == kAuthNone) ok = true;
    }
    unsigned char answer[2] = {kSocksVersion, static_cast<unsigned char>(ok ? kAuthNone : 0xFF)};
    if (!write_full(fd, answer, 2)) return false;
    return ok;
}

// Carries one accepted connection until either side is done.
void serve(socket_t client) {
    ++g_active;
    struct Guard {
        socket_t fd;
        ~Guard() {
            --g_active;
            if (fd != kInvalid) close(fd);
        }
    } guard{client};

    set_nonblocking(client);
    set_nodelay(client);

    if (!negotiate(client)) return;

    unsigned char head[4];
    if (!read_full(client, head, 4, 10000)) return;
    if (head[0] != kSocksVersion) return;
    if (head[1] != kCmdConnect) {
        // BIND / UDP ASSOCIATE: the tunnel is TCP-only.
        send_reply(client, 0x07);
        return;
    }

    std::string host;
    if (head[3] == kAtypIpv4) {
        unsigned char raw[4];
        if (!read_full(client, raw, 4, 10000)) return;
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", raw[0], raw[1], raw[2], raw[3]);
        host = buf;
    } else if (head[3] == kAtypIpv6) {
        unsigned char raw[16];
        if (!read_full(client, raw, 16, 10000)) return;
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x:%x", (raw[0] << 8) | raw[1],
                      (raw[2] << 8) | raw[3], (raw[4] << 8) | raw[5], (raw[6] << 8) | raw[7],
                      (raw[8] << 8) | raw[9], (raw[10] << 8) | raw[11], (raw[12] << 8) | raw[13],
                      (raw[14] << 8) | raw[15]);
        host = buf;
    } else if (head[3] == kAtypDomain) {
        unsigned char len = 0;
        if (!read_full(client, &len, 1, 10000)) return;
        if (len == 0) {
            send_reply(client, 0x08);
            return;
        }
        std::string name(len, '\0');
        if (!read_full(client, name.data(), len, 10000)) return;
        host = name;
    } else {
        send_reply(client, 0x08);
        return;
    }

    unsigned char port_raw[2];
    if (!read_full(client, port_raw, 2, 10000)) return;
    const int port = (port_raw[0] << 8) | port_raw[1];

    if (!wg_outbound_ready()) {
        send_reply(client, 0x01);
        return;
    }

    std::string error;
    std::unique_ptr<WgConnection> upstream = WgStack::instance().connect(host, port, 15000, error);
    if (!upstream) {
        if (bpb::log::enabled(bpb::log::kDebug))
            bpb::log::warn("[wg-socks] connect %s:%d failed: %s", host.c_str(), port,
                           error.c_str());
        send_reply(client, 0x05);
        return;
    }
    send_reply(client, 0x00);

    std::string pending;
    char buf[16384];
    bool client_open = true;

    for (;;) {
        if (g_draining.load()) break;
        // Poll the client for whatever it is ready to do, and never block for
        // long: pump() has to keep running so the tunnel stays driven.
        PollFd pfd{client, static_cast<short>(kRead | (pending.empty() ? 0 : kWrite)), 0};
        poll_fds(&pfd, 1, 20);
        if (pfd.revents & (kError | kHangup | kInvalidFd)) break;

        if (client_open && (pfd.revents & kRead)) {
            const int n = static_cast<int>(::recv(client, buf, sizeof(buf), 0));
            if (n > 0) {
                if (upstream->write(buf, n) < 0) break;
            } else if (n == 0) {
                client_open = false;
                if (pending.empty()) break;
            } else if (!would_block(last_error())) {
                break;
            }
        }

        if (!pending.empty() && (pfd.revents & kWrite)) {
            const int n = static_cast<int>(
                ::send(client, pending.data(), static_cast<int>(pending.size()), 0));
            if (n > 0) {
                pending.erase(0, static_cast<std::size_t>(n));
            } else if (n < 0 && !would_block(last_error())) {
                break;
            }
        }

        // Pull from the tunnel only while the client is keeping up. Without the
        // cap a slow reader turns into unbounded buffering here.
        while (pending.size() < kMaxPending) {
            const int n = upstream->read(buf, sizeof(buf), 0);
            if (n > 0) {
                pending.append(buf, static_cast<std::size_t>(n));
            } else if (n < 0) {
                // Origin closed: deliver what is buffered, then stop.
                while (!pending.empty()) {
                    const int sent = static_cast<int>(
                        ::send(client, pending.data(), static_cast<int>(pending.size()), 0));
                    if (sent > 0) {
                        pending.erase(0, static_cast<std::size_t>(sent));
                    } else if (sent < 0 && would_block(last_error())) {
                        PollFd w{client, kWrite, 0};
                        if (poll_fds(&w, 1, 1000) <= 0) break;
                    } else {
                        break;
                    }
                }
                return;
            } else {
                break;
            }
        }
    }
}

void accept_loop() {
    while (g_running.load()) {
        PollFd pfd{g_listener, kRead, 0};
        const int ready = poll_fds(&pfd, 1, 200);
        if (ready <= 0) continue;
        if (pfd.revents & (kError | kInvalidFd)) continue;

        sockaddr_in addr{};
#ifdef _WIN32
        int len = sizeof(addr);
#else
        socklen_t len = sizeof(addr);
#endif
        const socket_t fd = ::accept(g_listener, reinterpret_cast<sockaddr*>(&addr), &len);
        if (fd == kInvalid) {
            // A closed listener reports EBADF/EINVAL on every pass; stop rather
            // than spin. A transient EMFILE just skips this round.
            if (!g_running.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        // One thread per connection, like every other inbound in this process.
        bpb::util::spawn_detached([fd] { serve(fd); }, 128 * 1024);
    }
}

} // namespace

bool start_wg_socks(const std::string& bind_host, int port, std::string& error) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_running.load()) return true;
    if (port <= 0 || port > 65535) {
        error = "invalid socks port";
        return false;
    }

    socket_t fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kInvalid) {
        error = "socket() failed: " + error_string(last_error());
        return false;
    }
    set_reuseaddr(fd);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<unsigned short>(port));
    const std::string host = bind_host.empty() ? "127.0.0.1" : bind_host;
    if (host == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        error = "invalid socks bind host: " + host;
        return false;
    }

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int err = last_error();
        close(fd);
        error = "socks bind(" + host + ":" + std::to_string(port) + ") failed: " +
                error_string(err);
        return false;
    }
    if (::listen(fd, 128) != 0) {
        const int err = last_error();
        close(fd);
        error = "socks listen() failed: " + error_string(err);
        return false;
    }
    set_nonblocking(fd);
    g_listener = fd;
    g_bind_desc = host + ":" + std::to_string(port);
    g_running.store(true);
    g_accept_thread = std::thread(accept_loop);
    bpb::log::info("[wg-socks] SOCKS5 listening on %s", g_bind_desc.c_str());
    return true;
}

void stop_wg_socks() {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (!g_running.exchange(false)) {
        g_draining.store(false);
        return;
    }
    if (g_listener != kInvalid) {
        close(g_listener);
        g_listener = kInvalid;
    }
    if (g_accept_thread.joinable()) g_accept_thread.join();
    // Ask the relays to leave and give them a moment to do it. They are detached
    // (they must be: a relay blocks on a client socket), so this is a bounded
    // wait, not a join. Two seconds is far more than one loop iteration needs.
    g_draining.store(true);
    for (int waited = 0; waited < 40 && g_active.load() > 0; ++waited)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    g_draining.store(false);
    g_bind_desc.clear();
    bpb::log::info("[wg-socks] stopped");
}

bool wg_socks_running() { return g_running.load(); }

std::string wg_socks_status() {
    if (!g_running.load()) return "stopped";
    return g_bind_desc + " (" + std::to_string(g_active.load()) + " active)";
}

} // namespace bpb::net
