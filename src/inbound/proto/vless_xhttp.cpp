#include "inbound/inbound.h"
#include "inbound/proto/xhttp.h"

#include "proxy/session.h"
#include "net/net.h"
#include "net/tls.h"
#include "net/wg_outbound.h"
#include "util/log.h"
#include "util/thread.h"
#include "util/util.h"

// The two branches carry different WARP outbounds: warp-built-in runs lwIP in
// process (net/wg_stack.h), warp-rust drives an external sidecar over a SOCKS
// socket (net/warp_proc.h). The header probe keeps this file identical on both.
#if defined(__has_include)
#if __has_include("net/wg_stack.h")
#include "net/wg_stack.h"
#define BPB_XH_WG_STACK 1
#endif
#if __has_include("net/warp_proc.h")
#include "net/warp_proc.h"
#define BPB_XH_WARP_PROC 1
#endif
#endif

#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <random>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// VLESS carried by XHTTP (SplitHTTP).
//
// The transport (src/inbound/proto/xhttp.cpp) already turns the split stream
// into an ordered byte pipe, so this is the same relay as vless_ws.cpp with the
// websocket frame codec replaced by the session read/write:
//
//   client -> POST bodies -> session uplink  -> VLESS header, then payload
//   session downlink      -> chunked GET     <- VLESS 2-byte response, then data
//
// The copies of Outbound / connect / parse below are deliberate: this project
// lets every protocol carry its own copy (see ws_transport.h), so a change here
// can never regress a protocol that already ships.
namespace bpb::proxy {

namespace {

constexpr std::size_t kChunk = 16384;
// One poll() slice per direction: an idle session costs 20 wake-ups/second
// instead of the 2000 a 1 ms sleep would burn.
constexpr int kWaitSliceMs = 100;
// A session that delivers a few bytes and then nothing is either a broken
// client or a scanner; the header is sent immediately by every real client.
constexpr std::int64_t kHandshakeTimeoutMs = 30000;
// The VLESS request header is at most a few hundred bytes (16-byte id, addons,
// address). Anything larger means the bytes are not VLESS at all.
constexpr std::size_t kMaxHeaderBytes = 4096;
using net::socket_t;

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool send_all(SSL* ssl, socket_t fd, const char* data, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
        net::IoResult result = net::IoResult::Error;
        int n = net::tls_write(ssl, fd, data + sent, static_cast<int>(len - sent), result);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (result == net::IoResult::WouldBlock) {
            net::PollFd pfd{fd, net::kWrite, 0};
            if (net::poll_fds(&pfd, 1, 500) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

// Outbound abstraction: either a plain system socket or a connection carried
// inside the userspace WireGuard tunnel (WARP).
struct Outbound {
    socket_t fd = net::kInvalid;
#ifdef BPB_XH_WG_STACK
    std::unique_ptr<net::WgConnection> wg;
#endif

    bool valid() const {
        return fd != net::kInvalid
#ifdef BPB_XH_WG_STACK
               || wg != nullptr
#endif
            ;
    }

    // Reads up to len bytes. Returns >0, 0 on timeout, -1 on close.
    //
    // The socket is non-blocking, so a bare recv() returns EAGAIN the instant
    // the origin has nothing to say; poll() here is what makes timeout_ms mean
    // what the caller assumes, and what keeps an idle session off the CPU.
    int read(char* buf, int len, int timeout_ms) {
#ifdef BPB_XH_WG_STACK
        if (wg) return wg->read(buf, len, timeout_ms);
#endif
        int n = static_cast<int>(::recv(fd, buf, len, 0));
        if (n > 0) return n;
        if (n == 0) return -1;
        if (!net::would_block(net::last_error())) return -1;
        if (timeout_ms <= 0) return 0;
        net::PollFd pfd{fd, net::kRead, 0};
        const int pr = net::poll_fds(&pfd, 1, timeout_ms);
        if (pr == 0) return 0;
        if (pr < 0) return -1;
        n = static_cast<int>(::recv(fd, buf, len, 0));
        if (n > 0) return n;
        if (n == 0) return -1;
        if (net::would_block(net::last_error())) return 0;
        return -1;
    }

    bool write(const char* buf, std::size_t len) {
#ifdef BPB_XH_WG_STACK
        if (wg) return wg->write(buf, static_cast<int>(len)) == static_cast<int>(len);
#endif
        return send_all(nullptr, fd, buf, len);
    }

    void close() {
#ifdef BPB_XH_WG_STACK
        if (wg) { wg->close(); wg.reset(); }
#endif
        if (fd != net::kInvalid) { net::close(fd); fd = net::kInvalid; }
    }
};

socket_t connect_tcp(const std::string& host, int port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) return net::kInvalid;

    socket_t out = net::kInvalid;
    for (addrinfo* p = res; p; p = p->ai_next) {
        socket_t s = static_cast<socket_t>(::socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (s == net::kInvalid) continue;
#ifdef _WIN32
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
#else
        fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
        int rc = ::connect(s, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen));
        bool ok = (rc == 0);
        if (!ok && net::would_block(net::last_error())) {
            net::PollFd pfd{s, net::kWrite, 0};
            if (net::poll_fds(&pfd, 1, timeout_ms) > 0) {
                int soerr = 0;
                socklen_t l = sizeof(soerr);
                getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &l);
                ok = (soerr == 0);
            }
        }
        if (ok) {
            net::set_nonblocking(s);
            net::set_nodelay(s);
            out = s;
            break;
        }
        net::close(s);
    }
    freeaddrinfo(res);
    return out;
}

// Connects to host:port, preferring the WARP tunnel when it is ready. Falls back
// to a direct socket so the panel keeps working if WARP is unavailable.
Outbound connect_outbound(const std::string& host, int port, int timeout_ms) {
    Outbound ob;
#ifdef BPB_XH_WG_STACK
    // Loopback and RFC1918 destinations belong on a direct socket: the WARP
    // netif has no route to them (see inbound::is_local_target).
    if (!::bpb::inbound::is_local_target(host) && net::wg_outbound_ready()) {
        std::string err;
        auto conn = net::WgStack::instance().connect(host, port, timeout_ms, err);
        if (conn && conn->valid()) {
            ob.wg = std::move(conn);
            return ob;
        }
    }
#elif defined(BPB_XH_WARP_PROC)
    if (net::wg_outbound_ready()) {
        socket_t s = net::warp_socks_connect(host, port, timeout_ms);
        if (s != net::kInvalid) {
            ob.fd = s;
            return ob;
        }
    }
#else
    (void)host;
#endif
    ob.fd = connect_tcp(host, port, timeout_ms);
    return ob;
}

struct Addr {
    std::string host;
    int port = 0;
    // Set when parsing stopped only because more bytes are needed; the first
    // POST often ends in the middle of the address.
    bool need_more = false;
};

// Parses atyp + address starting at pos (no port). Returns false when incomplete.
bool parse_atyp_addr(const std::string& buf, std::size_t& pos, Addr& addr) {
    if (pos >= buf.size()) { addr.need_more = true; return false; }
    int atyp = static_cast<unsigned char>(buf[pos++]);
    if (atyp == 1) {
        if (pos + 4 > buf.size()) { addr.need_more = true; return false; }
        char ip[32];
        std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u", static_cast<unsigned char>(buf[pos]),
                      static_cast<unsigned char>(buf[pos + 1]),
                      static_cast<unsigned char>(buf[pos + 2]),
                      static_cast<unsigned char>(buf[pos + 3]));
        addr.host = ip;
        pos += 4;
    } else if (atyp == 2) {
        if (pos >= buf.size()) { addr.need_more = true; return false; }
        std::size_t len = static_cast<unsigned char>(buf[pos++]);
        if (pos + len > buf.size()) { addr.need_more = true; return false; }
        addr.host = buf.substr(pos, len);
        pos += len;
    } else if (atyp == 3) {
        if (pos + 16 > buf.size()) { addr.need_more = true; return false; }
        char ip[64];
        std::snprintf(ip, sizeof(ip),
                      "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
                      static_cast<unsigned char>(buf[pos]), static_cast<unsigned char>(buf[pos + 1]),
                      static_cast<unsigned char>(buf[pos + 2]), static_cast<unsigned char>(buf[pos + 3]),
                      static_cast<unsigned char>(buf[pos + 4]), static_cast<unsigned char>(buf[pos + 5]),
                      static_cast<unsigned char>(buf[pos + 6]), static_cast<unsigned char>(buf[pos + 7]),
                      static_cast<unsigned char>(buf[pos + 8]), static_cast<unsigned char>(buf[pos + 9]),
                      static_cast<unsigned char>(buf[pos + 10]), static_cast<unsigned char>(buf[pos + 11]),
                      static_cast<unsigned char>(buf[pos + 12]), static_cast<unsigned char>(buf[pos + 13]),
                      static_cast<unsigned char>(buf[pos + 14]), static_cast<unsigned char>(buf[pos + 15]));
        addr.host = ip;
        pos += 16;
    } else {
        return false;
    }
    return true;
}

bool read_port(const std::string& buf, std::size_t& pos, Addr& addr) {
    if (pos + 2 > buf.size()) return false;
    addr.port = (static_cast<unsigned char>(buf[pos]) << 8) | static_cast<unsigned char>(buf[pos + 1]);
    pos += 2;
    return true;
}

// need_more means "not enough bytes yet, wait for the next POST body"; the
// two failure kinds must not be conflated, because a split header is normal
// (the transport cuts the stream wherever the client's packets land).
bool parse_vless(const std::string& buf, const std::string& uuid, Addr& addr,
                 std::size_t& header_len, std::string& response_header, bool& need_more) {
    need_more = false;
    if (buf.size() < 18) { need_more = true; return false; }
    int version = static_cast<unsigned char>(buf[0]);
    const std::string uuid_bytes = buf.substr(1, 16);
    // The credential IS this 16-byte id: without the comparison the inbound
    // accepts any uuid and turns into an open proxy.
    std::string clean;
    clean.reserve(32);
    for (char c : uuid) {
        if (c != '-' && c != ' ') clean.push_back(c);
    }
    if (clean.size() != 32) return false;   // malformed configured uuid: fail closed
    std::string expected;
    expected.reserve(16);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        const auto hex = [](char h) -> int {
            if (h >= '0' && h <= '9') return h - '0';
            if (h >= 'a' && h <= 'f') return h - 'a' + 10;
            if (h >= 'A' && h <= 'F') return h - 'A' + 10;
            return -1;
        };
        const int hi = hex(clean[i]);
        const int lo = hex(clean[i + 1]);
        if (hi < 0 || lo < 0) return false;
        expected.push_back(static_cast<char>((hi << 4) | lo));
    }
    if (expected != uuid_bytes) return false;

    std::size_t pos = 17;
    std::size_t addons_len = static_cast<unsigned char>(buf[pos++]);
    if (buf.size() < pos + addons_len + 1) { need_more = true; return false; }
    pos += addons_len;
    int command = static_cast<unsigned char>(buf[pos++]);
    if (command != 1) return false;   // only TCP
    if (pos + 2 > buf.size()) { need_more = true; return false; }
    if (!read_port(buf, pos, addr)) return false;
    if (!parse_atyp_addr(buf, pos, addr)) { need_more = addr.need_more; return false; }
    header_len = pos;

    response_header.push_back(static_cast<char>(version));
    response_header.push_back(0);
    return true;
}

bool resolve_target(const std::string& host, int port, const SessionConfig& config, Addr& out) {
    if (config.proxy_ip_mode == "proxyip" && !config.proxy_ips.empty()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<std::size_t> dist(0, config.proxy_ips.size() - 1);
        std::string proxy = config.proxy_ips[dist(gen)];
        auto parts = split(proxy, ':');
        if (parts.size() == 2) {
            out.host = parts[0];
            out.port = std::atoi(parts[1].c_str());
            return true;
        }
        if (parts.size() == 1) {
            out.host = parts[0];
            out.port = port;
            return true;
        }
    }
    out = Addr{host, port};
    return true;
}

// One XHTTP session as a byte stream: the VLESS handshake lives in the first
// uplink bytes, the response header is the first downlink bytes.
void session_loop(const xhttp::SessionPtr& sess, const SessionConfig& config) {
    Outbound upstream;
    std::string response_header;
    unsigned long long to_upstream = 0;   // VLESS payload bytes handed to the target
    unsigned long long to_client = 0;     // payload bytes written back to the client
    // Why the loop ended. Every exit path sets this so a stalled session can be
    // diagnosed from the log instead of guessed at.
    std::atomic<const char*> exitReason{"session finished"};
    bool need_more = false;

    auto try_connect = [&](const std::string& data) -> bool {
        Addr addr;
        std::size_t header_len = 0;
        need_more = false;
        const bool parsed =
            parse_vless(data, config.vl_uuid, addr, header_len, response_header, need_more);
        if (!parsed) return false;

        Addr target;
        resolve_target(addr.host, addr.port, config, target);
        if (bpb::log::enabled(bpb::log::kDebug))
            std::fprintf(stderr, "[xh] vless -> %s:%d (header %zu bytes)\n", target.host.c_str(),
                         target.port, header_len);
        upstream = connect_outbound(target.host, target.port, 8000);
        if (!upstream.valid()) {
            bpb::log::warn("[xh] upstream connect failed: %s:%d", target.host.c_str(), target.port);
            return false;
        }

        // The VLESS answer (version, 0) travels down the GET, and it must be the
        // first thing the client sees there.
        if (!response_header.empty() &&
            !xhttp::write_downlink(sess, response_header.data(), response_header.size()))
            return false;
        if (data.size() > header_len) {
            const std::string rest = data.substr(header_len);
            if (!upstream.write(rest.data(), rest.size())) return false;
            to_upstream += rest.size();
        }
        return true;
    };

    std::atomic<bool> finished{false};
    std::atomic<bool> upstreamReady{false};
    std::mutex gateMutex;
    std::condition_variable gateCv;
    auto gateOpen = [&] {
        {
            std::lock_guard<std::mutex> lk(gateMutex);
        }
        gateCv.notify_all();
    };

    // ---- client -> upstream ------------------------------------------------
    // Also owns the VLESS handshake: the target address only becomes known once
    // enough uplink bytes have arrived, which may take several POSTs.
    bpb::util::Thread toUpstream;
    toUpstream.start([&] {
        std::string hasBuf;
        hasBuf.reserve(64);
        char buf[kChunk];
        const std::int64_t handshakeDeadline = now_ms() + kHandshakeTimeoutMs;
        try {
            while (!finished.load()) {
                if (!upstreamReady.load()) {
                    // Nothing came at all: stop before parking two threads for
                    // the uptime on a session that will never parse.
                    if (now_ms() > handshakeDeadline) {
                        exitReason = "handshake timeout";
                        break;
                    }
                }
                const int n = xhttp::read_uplink(sess, buf, static_cast<int>(sizeof(buf)),
                                                 kWaitSliceMs);
                if (n < 0) {
                    exitReason = "client closed";
                    break;
                }
                if (n == 0) continue;

                if (!upstreamReady.load()) {
                    hasBuf.append(buf, static_cast<std::size_t>(n));
                    const bool ok = try_connect(hasBuf);
                    if (ok) {
                        hasBuf.clear();
                        upstreamReady.store(true);
                        gateOpen();   // release the download direction
                    } else if (!need_more || hasBuf.size() > kMaxHeaderBytes) {
                        exitReason = "handshake rejected";
                        break;
                    }
                    continue;
                }
                if (!upstream.write(buf, static_cast<std::size_t>(n))) {
                    exitReason = "upstream write failed";
                    break;
                }
                to_upstream += static_cast<unsigned long long>(n);
            }
        } catch (...) {
            exitReason = "exception in upload thread";
        }
        finished.store(true);
        gateOpen();
    });

    // ---- upstream -> client ------------------------------------------------
    bpb::util::Thread toClient;
    toClient.start([&] {
        char buf[kChunk];
        try {
            while (!finished.load()) {
                if (!upstreamReady.load()) {
                    std::unique_lock<std::mutex> lk(gateMutex);
                    gateCv.wait_for(lk, std::chrono::milliseconds(kWaitSliceMs),
                                    [&] { return upstreamReady.load() || finished.load(); });
                    continue;
                }
                const int n = upstream.read(buf, sizeof(buf), kWaitSliceMs);
                if (n < 0) {
                    exitReason = "upstream closed";
                    break;
                }
                if (n == 0) continue;
                if (!xhttp::write_downlink(sess, buf, static_cast<std::size_t>(n))) {
                    exitReason = "client write failed";
                    break;
                }
                to_client += static_cast<unsigned long long>(n);
            }
        } catch (...) {
            exitReason = "exception in download thread";
        }
        finished.store(true);
    });

    // Whichever direction stops first sets finished and the other notices on its
    // next slice: the uplink read is bounded by the session wait and the origin
    // read by 100 ms, so neither can hang the session.
    toUpstream.join();
    finished.store(true);
    toClient.join();

    if (bpb::log::enabled(bpb::log::kDebug))
        std::fprintf(stderr, "[xh] session end: up=%llu down=%llu reason=%s\n", to_upstream,
                     to_client, exitReason.load());
    upstream.close();
}

// Transport callback: one relay session per XHTTP stream. The transport already
// owns the sockets; this thread only moves bytes.
void vless_xhttp_attach(xhttp::SessionPtr sess, const SessionConfig& config) {
    const bool started = bpb::util::spawn_detached(
        [sess, config] {
            session_loop(sess, config);
            // Flushes the downlink (chunked terminator) and drops the table
            // entry, so the next session with this id starts from scratch.
            xhttp::finish(sess);
            // Hand this session's pages back to the kernel instead of parking
            // them in a glibc arena: 200 short sessions otherwise leave an idle
            // relay several MB above its cold-start RSS.
            bpb::util::release_free_memory();
        },
        128 * 1024);
    if (!started) {
        // No relay thread: this session can never carry a byte, so end it now
        // instead of holding the table entry and the client's connection.
        bpb::log::warn("[xh] no thread for the VLESS relay, dropping the session");
        xhttp::finish(sess);
    }
}

} // namespace

// Registered for the panel and the path table. XHTTP is not a websocket
// transport, so the websocket entry point only ever answers a client that
// upgraded at this path by mistake.
void vless_xhttp_serve(net::socket_t client_fd, SSL* client_ssl, std::string accept_key,
                       std::string path, std::string ws_protocol, SessionConfig config) {
    (void)accept_key;
    (void)path;
    (void)ws_protocol;
    (void)config;
    static const char kBad[] =
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    send_all(client_ssl, client_fd, kBad, sizeof(kBad) - 1);
    if (client_ssl) {
        SSL_shutdown(client_ssl);
        net::tls_free(client_ssl);
    }
    if (client_fd != net::kInvalid) net::close(client_fd);
}

} // namespace bpb::proxy

// Bind the protocol to the transport at load time. Without this the transport
// answers nothing (it returns false and the panel serves the request), so a
// build that leaves this file out simply has no XHTTP.
namespace {
struct XhttpBinding {
    XhttpBinding() { ::bpb::proxy::xhttp::set_attach(&::bpb::proxy::vless_xhttp_attach); }
};
[[maybe_unused]] XhttpBinding g_xhttp_binding;
} // namespace

// Registered by src/inbound/registry.cpp when -DBPB_INBOUNDS includes vless.
namespace bpb::inbound {
// extern: a plain const at namespace scope has internal linkage in C++, so
// registry.cpp would not see it.
extern const Inbound vless_xhttp_inbound = {"vless-xhttp", "vlx", "VLESS (XHTTP)",
                                            &::bpb::proxy::vless_xhttp_serve};
} // namespace bpb::inbound
