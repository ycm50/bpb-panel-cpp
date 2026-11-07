#include "inbound/inbound.h"

#include "net/net.h"
#include "net/tls.h"
#include "net/wg_outbound.h"
#include "net/wg_stack.h"
#include "util/budget.h"
#include "util/log.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>   // tcp_keepalive / SIO_KEEPALIVE_VALS
#else
#include <netdb.h>
#include <netinet/tcp.h>   // TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT
#include <sys/socket.h>
#include <unistd.h>
#endif

// Trojan inbound, WebSocket wrapped. Wire format follows XTLS/Xray-core
// proxy/trojan/protocol.go (ConnWriter.writeHeader) and the server side in
// proxy/trojan/server.go:
//
//     hex(SHA224(password))   56 ASCII bytes
//     CRLF
//     command                 1 byte, 0x01 = TCP (0x03 = UDP, not served here)
//     address                 ATYP + address + port, SOCKS5 style
//     CRLF
//     payload                 the rest of the stream
//
// The address families are the SOCKS5 ones (0x01 IPv4, 0x03 domain, 0x04 IPv6),
// which is NOT the VLESS order -- the two protocols disagree, so sharing a
// parser would silently accept the wrong one.
//
// The server sends nothing back before relaying: no challenge, no ack.
// Authentication is the hash, and a wrong hash is simply a closed connection.

namespace bpb::proxy {
namespace {

constexpr std::size_t kChunk = 16384;
constexpr std::size_t kHashLen = 56;   // 28 byte digest, hex encoded
constexpr std::size_t kHeaderMin = kHashLen + 2;

// How long a websocket frame may sit unflushed before the peer is declared dead.
// Any successful write resets the timer, so this is "no progress for 60s", not
// "this frame took 60s" -- a slow-but-alive client keeps making progress.
constexpr int kSendStallMs = 60000;

// One poll() slice per direction. Idle cost is 10 wake-ups/second/session
// instead of the 1000 the 1 ms sleep this replaces produced.
constexpr int kWaitSliceMs = 100;

// A websocket that upgrades and then never sends its Trojan header keeps a
// thread and an fd for ever (a browser or a scanner poking /tr is enough). The
// header is sent immediately by every real client, so this only ever catches
// sockets that are already dead.
constexpr std::int64_t kHandshakeTimeoutMs = 30000;

// Dead eyes are invisible to a relay: the CF edge can vanish without a FIN, and
// the session then waits for bytes that will never come. TCP keepalive makes the
// kernel notice (~60 s idle + 4 probes) so the read fails and the session can be
// torn down instead of lingering as a thread.
void enable_keepalive(net::socket_t fd) {
    if (fd == net::kInvalid) return;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
               reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef _WIN32
    tcp_keepalive ka{1, 60000, 15000};
    DWORD bytes = 0;
    WSAIoctl(fd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes, nullptr, nullptr);
#else
    int idle = 60;      // seconds before the first probe
    int intvl = 15;     // seconds between probes
    int cnt = 4;        // probes before the socket is declared dead
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

bool send_all(SSL* ssl, net::socket_t fd, const char* data, std::size_t len) {
    std::size_t off = 0;
    int stalled_ms = 0;
    while (off < len) {
        net::IoResult result = net::IoResult::Error;
        const int n = net::tls_write(ssl, fd, data + off, static_cast<int>(len - off), result);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            stalled_ms = 0;
            continue;
        }
        if (result != net::IoResult::WouldBlock) return false;
        // The socket is non-blocking and the peer's window is full: this is the
        // normal case for a big download or a slow origin, NOT an error. Bailing
        // out here abandons a half-written frame, so the client sees a truncated
        // body (64 MB download stopping at 45 MB) and the origin sees a truncated
        // upload. Wait for writability and keep going.
        net::PollFd pfd{fd, net::kWrite, 0};
        if (net::poll_fds(&pfd, 1, 500) <= 0) {
            stalled_ms += 500;
            if (stalled_ms > kSendStallMs) return false;   // peer really is gone
            continue;
        }
        stalled_ms = 0;
    }
    return true;
}

std::string sha224_hex(const std::string& password) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::string();
    EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr);
    EVP_DigestUpdate(ctx, password.data(), password.size());
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out += kHex[digest[i] >> 4];
        out += kHex[digest[i] & 0x0F];
    }
    return out;
}

// >0 bytes, 0 on timeout, -1 when the peer closed.
int read_some(SSL* ssl, net::socket_t fd, char* buf, int cap, int timeout_ms) {
    if (ssl) {
        if (SSL_pending(ssl) <= 0) {
            net::PollFd pfd{fd, net::kRead, 0};
            if (net::poll_fds(&pfd, 1, timeout_ms) <= 0) return 0;
        }
        int n = SSL_read(ssl, buf, cap);
        if (n > 0) return n;
        const int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        return -1;
    }
    // The plain (non-TLS) socket is non-blocking too, so a bare recv() returns
    // EAGAIN the instant the peer has nothing to say. Returning 0 immediately
    // turned the caller's slice into a recv()/EAGAIN hot loop that pinned a core
    // for every established-but-idle session; poll() makes timeout_ms real.
    int n = static_cast<int>(::recv(fd, buf, cap, 0));
    if (n > 0) return n;
    if (n == 0) return -1;
    if (!net::would_block(net::last_error())) return -1;
    if (timeout_ms <= 0) return 0;
    net::PollFd pfd{fd, net::kRead, 0};
    const int pr = net::poll_fds(&pfd, 1, timeout_ms);
    if (pr == 0) return 0;                       // slice elapsed, session idle
    if (pr < 0) return -1;
    n = static_cast<int>(::recv(fd, buf, cap, 0));
    if (n > 0) return n;
    if (n == 0) return -1;
    if (net::would_block(net::last_error())) return 0;
    return -1;
}
// Outbound side: a plain socket, or the userspace WireGuard stack when it is up.
struct Outbound {
    net::socket_t fd = net::kInvalid;
    std::unique_ptr<net::WgConnection> wg;

    bool valid() const { return fd != net::kInvalid || wg != nullptr; }
    int read(char* buf, int len, int timeout_ms) {
        if (wg) return wg->read(buf, len, timeout_ms);
        return read_some(nullptr, fd, buf, len, timeout_ms);
    }
    bool write(const char* buf, std::size_t len) {
        if (wg) return wg->write(buf, static_cast<int>(len)) == static_cast<int>(len);
        return send_all(nullptr, fd, buf, len);
    }
    void close() {
        if (wg) { wg->close(); wg.reset(); }
        if (fd != net::kInvalid) { net::close(fd); fd = net::kInvalid; }
    }
};

net::socket_t connect_tcp(const std::string& host, int port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) return net::kInvalid;

    net::socket_t out = net::kInvalid;
    for (addrinfo* p = res; p; p = p->ai_next) {
        net::socket_t s = static_cast<net::socket_t>(
            ::socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (s == net::kInvalid) continue;
        net::set_nonblocking(s);
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

Outbound connect_outbound(const std::string& host, int port, int timeout_ms) {
    Outbound ob;
    // Loopback and RFC1918 destinations belong on a direct socket: the WARP
    // netif has no route to them and dialling them through it failed inside
    // lwIP (see inbound::is_local_target).
    if (!::bpb::inbound::is_local_target(host) && net::wg_outbound_ready()) {
        std::string err;
        auto conn = net::WgStack::instance().connect(host, port, timeout_ms, err);
        if (conn && conn->valid()) {
            ob.wg = std::move(conn);
            return ob;
        }
    }
    ob.fd = connect_tcp(host, port, timeout_ms);
    return ob;
}

bool ws_send(SSL* ssl, net::socket_t fd, const char* data, std::size_t len) {
    char head[10];
    std::size_t headLen = 0;
    head[headLen++] = static_cast<char>(0x82);  // FIN + binary
    if (len < 126) {
        head[headLen++] = static_cast<char>(len);
    } else if (len < 65536) {
        head[headLen++] = static_cast<char>(126);
        head[headLen++] = static_cast<char>((len >> 8) & 0xFF);
        head[headLen++] = static_cast<char>(len & 0xFF);
    } else {
        head[headLen++] = static_cast<char>(127);
        for (int i = 7; i >= 0; --i) head[headLen++] = static_cast<char>((len >> (i * 8)) & 0xFF);
    }
    if (!send_all(ssl, fd, head, headLen)) return false;
    return len == 0 || send_all(ssl, fd, data, len);
}

// Decoded client->server WebSocket stream. Control frames are answered here so a
// ping in the middle of a transfer does not look like the peer going away.
struct WsIn {
    SSL* ssl = nullptr;
    net::socket_t fd = net::kInvalid;
    std::string raw;      // bytes straight off the socket
    std::string pending;  // decoded application bytes not yet consumed
    // Absolute deadline for the header handshake; the per-step limits in
    // parse_header are a stall guard, this is the overall cap. max() until the
    // handshake starts so that relay-only reads are never cut short.
    std::chrono::steady_clock::time_point deadline{
        std::chrono::steady_clock::time_point::max()};

    // false when the peer closed or the socket failed.
    bool pump(int timeout_ms) {
        for (;;) {
            char buf[kChunk];
            const int n = read_some(ssl, fd, buf, static_cast<int>(sizeof(buf)), timeout_ms);
            if (n < 0) return false;
            if (n > 0) raw.append(buf, static_cast<std::size_t>(n));
            bool progressed = false;
            for (;;) {
                if (raw.size() < 2) break;
                const unsigned char b0 = static_cast<unsigned char>(raw[0]);
                const unsigned char b1 = static_cast<unsigned char>(raw[1]);
                const int opcode = b0 & 0x0F;
                const bool masked = (b1 & 0x80) != 0;
                std::uint64_t len = b1 & 0x7F;
                std::size_t off = 2;
                if (len == 126) {
                    if (raw.size() < 4) break;
                    len = (static_cast<unsigned char>(raw[2]) << 8) |
                          static_cast<unsigned char>(raw[3]);
                    off = 4;
                } else if (len == 127) {
                    if (raw.size() < 10) break;
                    len = 0;
                    for (int i = 0; i < 8; ++i) {
                        len = (len << 8) | static_cast<unsigned char>(raw[2 + i]);
                    }
                    off = 10;
                }
                unsigned char mask[4] = {0, 0, 0, 0};
                if (masked) {
                    if (raw.size() < off + 4) break;
                    std::memcpy(mask, raw.data() + off, 4);
                    off += 4;
                }
                if (raw.size() < off + len) break;
                std::string body = raw.substr(off, static_cast<std::size_t>(len));
                raw.erase(0, off + static_cast<std::size_t>(len));
                if (masked) {
                    for (std::size_t i = 0; i < body.size(); ++i) {
                        body[i] = static_cast<char>(body[i] ^ mask[i & 3]);
                    }
                }
                if (opcode == 0x8) return false;
                if (opcode == 0x9) {
                    char pong[2] = {static_cast<char>(0x8A), static_cast<char>(body.size() & 0x7F)};
                    send_all(ssl, fd, pong, 2);
                    send_all(ssl, fd, body.data(), body.size());
                    continue;
                }
                if (opcode == 0xA) continue;
                pending += body;
                progressed = true;
            }
            if (n <= 0 && !progressed) return true;  // timeout, nothing new
        }
    }
};
// Waits until `n` decoded bytes are buffered. Bounded by `limit_ms` (a single
// stall) and by in.deadline (the whole handshake) so a peer that opens the socket
// and dribbles one byte at a time cannot keep a thread and an fd forever.
bool ensure(WsIn& in, std::size_t n, int limit_ms) {
    const auto start = std::chrono::steady_clock::now();
    while (in.pending.size() < n) {
        if (!in.pump(kWaitSliceMs)) return false;
        const auto now = std::chrono::steady_clock::now();
        if (now > in.deadline) return false;   // handshake took too long
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (ms > limit_ms) return false;
    }
    return true;
}

struct Header {
    std::string host;
    int port = 0;
    std::string payload;
};

bool parse_header(WsIn& in, const std::string& expect, Header& out) {
    in.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeTimeoutMs);
    if (!ensure(in, kHeaderMin, 10000)) return false;
    if (in.pending.compare(0, kHashLen, expect) != 0) {
        log::debug("[trojan] password hash mismatch");
        return false;
    }
    if (in.pending[kHashLen] != '\r' || in.pending[kHashLen + 1] != '\n') {
        log::debug("[trojan] missing CRLF after the password");
        return false;
    }
    std::size_t pos = kHeaderMin;
    if (!ensure(in, pos + 1, 10000)) return false;
    const unsigned char cmd = static_cast<unsigned char>(in.pending[pos++]);
    if (cmd != 0x01) {
        log::debug("[trojan] command %u is not TCP", static_cast<unsigned>(cmd));
        return false;
    }
    if (!ensure(in, pos + 1, 10000)) return false;
    const unsigned char atyp = static_cast<unsigned char>(in.pending[pos++]);
    if (atyp == 0x01) {
        if (!ensure(in, pos + 4, 10000)) return false;
        char ip[32];
        std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                      static_cast<unsigned char>(in.pending[pos]),
                      static_cast<unsigned char>(in.pending[pos + 1]),
                      static_cast<unsigned char>(in.pending[pos + 2]),
                      static_cast<unsigned char>(in.pending[pos + 3]));
        out.host = ip;
        pos += 4;
    } else if (atyp == 0x03) {
        if (!ensure(in, pos + 1, 10000)) return false;
        const std::size_t len = static_cast<unsigned char>(in.pending[pos++]);
        if (!ensure(in, pos + len, 10000)) return false;
        out.host = in.pending.substr(pos, len);
        pos += len;
    } else if (atyp == 0x04) {
        if (!ensure(in, pos + 16, 10000)) return false;
        char ip[64];
        std::snprintf(ip, sizeof(ip),
                      "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
                      static_cast<unsigned char>(in.pending[pos]),
                      static_cast<unsigned char>(in.pending[pos + 1]),
                      static_cast<unsigned char>(in.pending[pos + 2]),
                      static_cast<unsigned char>(in.pending[pos + 3]),
                      static_cast<unsigned char>(in.pending[pos + 4]),
                      static_cast<unsigned char>(in.pending[pos + 5]),
                      static_cast<unsigned char>(in.pending[pos + 6]),
                      static_cast<unsigned char>(in.pending[pos + 7]),
                      static_cast<unsigned char>(in.pending[pos + 8]),
                      static_cast<unsigned char>(in.pending[pos + 9]),
                      static_cast<unsigned char>(in.pending[pos + 10]),
                      static_cast<unsigned char>(in.pending[pos + 11]),
                      static_cast<unsigned char>(in.pending[pos + 12]),
                      static_cast<unsigned char>(in.pending[pos + 13]),
                      static_cast<unsigned char>(in.pending[pos + 14]),
                      static_cast<unsigned char>(in.pending[pos + 15]));
        out.host = ip;
        pos += 16;
    } else {
        log::debug("[trojan] address type %u is not supported",
                   static_cast<unsigned>(atyp));
        return false;
    }
    if (!ensure(in, pos + 4, 10000)) return false;
    out.port = (static_cast<unsigned char>(in.pending[pos]) << 8) |
               static_cast<unsigned char>(in.pending[pos + 1]);
    pos += 2;
    if (in.pending[pos] != '\r' || in.pending[pos + 1] != '\n') {
        log::debug("[trojan] missing CRLF after the address");
        return false;
    }
    pos += 2;
    out.payload = in.pending.substr(pos);
    in.pending.clear();
    return true;
}

// One thread per direction, like the VLESS inbound: a blocking read on one side
// must not stop the other from draining.
// Takes the SAME WsIn the header was parsed from: it still holds the bytes of
// any websocket frame that arrived partially with the header, and a fresh one
// would drop them and desync the frame stream (the origin then waits forever
// for a body whose first frame can never be completed).
void relay(SSL* ssl, net::socket_t client, Outbound& ob, WsIn& in, const std::string& first) {
    if (!first.empty() && !ob.write(first.data(), first.size())) return;
    std::atomic<bool> stop{false};
    std::thread upstream([&] {
        while (!stop.load()) {
            // pump() blocks in poll() for one slice, so this thread sleeps
            // instead of spinning on recv()/EAGAIN.
            if (!in.pump(kWaitSliceMs)) break;
            if (!in.pending.empty()) {
                const bool ok = ob.write(in.pending.data(), in.pending.size());
                in.pending.clear();
                if (!ok) break;
            }
        }
        stop.store(true);
    });
    // The buffer starts small and widens only after a read that filled it: that
    // is the one signal that says a larger window would actually raise
    // throughput here, and it keeps idle sessions cheap.
    bpb::util::RelayBuffer rb;
    while (!stop.load()) {
        // read() polls for up to one slice: an idle session costs one wake-up
        // per slice, not a hot loop.
        const int n = ob.read(rb.data(), static_cast<int>(rb.size()), kWaitSliceMs);
        if (n < 0) break;
        if (n > 0) {
            const bool full = static_cast<std::size_t>(n) == rb.size();
            if (!ws_send(ssl, client, rb.data(), static_cast<std::size_t>(n))) break;
            if (full) rb.grow();
        }
    }
    stop.store(true);
    upstream.join();
    ob.close();
}

void trojan_serve(net::socket_t client, SSL* ssl, std::string accept_key, std::string path,
                  std::string ws_protocol, SessionConfig cfg) {
    (void)path;
    (void)ws_protocol;  // no early data in Trojan: the hash travels as payload

    // Admission before the upgrade and before any session resource is created;
    // an over-capacity client gets a 503 it can retry instead of a half-open
    // websocket.
    auto permit = bpb::util::SessionPermit::try_acquire();
    if (!permit) {
        static const char busy[] = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\n"
                                   "Content-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(ssl, client, busy, sizeof(busy) - 1);
        if (ssl) net::tls_free(ssl);
        net::close(client);
        return;
    }
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n";
    if (!accept_key.empty()) response += "Sec-WebSocket-Accept: " + accept_key + "\r\n";
    response += "\r\n";
    if (!send_all(ssl, client, response.data(), response.size())) {
        if (ssl) net::tls_free(ssl);
        net::close(client);
        return;
    }

    // The password is the same credential the panel already manages for VLESS:
    // one UUID per panel, used verbatim as the Trojan password.
    const std::string expect = sha224_hex(cfg.vl_uuid);
    std::thread([client, ssl, expect, cfg, permit] {
        enable_keepalive(client);
        WsIn in;
        in.ssl = ssl;
        in.fd = client;
        Header head;
        if (parse_header(in, expect, head)) {
            Outbound ob = connect_outbound(head.host, head.port, 15000);
            if (ob.valid()) {
                log::debug("[trojan] %s:%d", head.host.c_str(), head.port);
                relay(ssl, client, ob, in, head.payload);
            } else {
                log::debug("[trojan] cannot reach %s:%d", head.host.c_str(), head.port);
            }
        }
        if (ssl) net::tls_free(ssl);
        net::close(client);
    }).detach();
}

} // namespace
} // namespace bpb::proxy

// Registered by src/inbound/registry.cpp when -DBPB_INBOUNDS includes trojan.
namespace bpb::inbound {
// extern: a plain const at namespace scope has internal linkage, so registry.cpp
// would not see it.
extern const Inbound trojan_inbound = {"trojan", "tr", "Trojan", &::bpb::proxy::trojan_serve};
} // namespace bpb::inbound