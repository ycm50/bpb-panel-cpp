#pragma once
// WebSocket transport helpers shared by the inbound protocol implementations.
//
// Every protocol file used to carry its own copy of the frame codec and the
// outbound dialer. New protocols include this header instead of copying another
// few hundred lines; existing ones keep their local copies so that a change here
// can never regress a protocol that already ships.
#include "inbound/inbound.h"

#include "proxy/session.h"
#include "net/net.h"
#include "net/tls.h"
#include "net/wg_outbound.h"

// The two branches carry different WARP outbounds: warp-built-in runs lwIP in
// process (net/wg_stack.h), warp-rust drives an external sidecar over a SOCKS
// socket (net/warp_proc.h). Detect which one exists so this header is identical
// on both branches and the protocol code never has to care.
#if defined(__has_include)
#if __has_include("net/wg_stack.h")
#include "net/wg_stack.h"
#define BPB_WSX_WG_STACK 1
#endif
#if __has_include("net/warp_proc.h")
#include "net/warp_proc.h"
#define BPB_WSX_WARP_PROC 1
#endif
#endif

#include <openssl/ssl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
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

namespace bpb::proxy::wsx {

constexpr std::size_t kChunk = 16384;
using net::socket_t;

// send() that keeps going through short writes and WouldBlock. A websocket
// frame must never be abandoned half-way: the peer would read a truncated frame
// and drop the stream even though the payload was fine.
inline bool send_all(SSL* ssl, socket_t fd, const char* data, std::size_t len) {
    std::size_t sent = 0;
    int stalls = 0;
    while (sent < len) {
        net::IoResult result = net::IoResult::Error;
        int n = net::tls_write(ssl, fd, data + sent, static_cast<int>(len - sent), result);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (result == net::IoResult::WouldBlock) {
            net::PollFd pfd{fd, net::kWrite, 0};
            if (net::poll_fds(&pfd, 1, 500) <= 0) {
                if (++stalls > 20) return false;   // ~10s with no progress
                continue;
            }
            stalls = 0;
            continue;
        }
        return false;
    }
    return true;
}

inline void frame_header(std::string& out, int opcode, std::size_t len) {
    out.push_back(static_cast<char>(0x80 | (opcode & 0x0F)));
    if (len < 126) {
        out.push_back(static_cast<char>(len));
    } else if (len <= 0xFFFF) {
        out.push_back(126);
        out.push_back(static_cast<char>((len >> 8) & 0xFF));
        out.push_back(static_cast<char>(len & 0xFF));
    } else {
        out.push_back(127);
        for (int i = 7; i >= 0; --i) out.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
    }
}

inline bool ws_send(SSL* ssl, socket_t fd, const char* data, std::size_t len, int opcode = 0x2) {
    std::string header;
    frame_header(header, opcode, len);
    if (!send_all(ssl, fd, header.data(), header.size())) return false;
    if (len == 0) return true;
    return send_all(ssl, fd, data, len);
}

// Result of a non-blocking frame read.
enum class FrameState { Ok, Closed, Error, NeedMore };

// Reads one websocket frame payload into out. Never blocks waiting for a frame:
// returning NeedMore lets the caller keep servicing the other direction, which
// is what keeps a large download from freezing (see vless_ws.cpp).
inline FrameState read_frame(SSL* ssl, socket_t fd, std::string& pending, std::string& payload,
                             int& opcode) {
    while (true) {
        if (pending.size() >= 2) {
            unsigned char b0 = static_cast<unsigned char>(pending[0]);
            unsigned char b1 = static_cast<unsigned char>(pending[1]);
            bool masked = (b1 & 0x80) != 0;
            std::uint64_t len = b1 & 0x7F;
            std::size_t hdr = 2;
            if (len == 126) hdr = 4;
            else if (len == 127) hdr = 10;

            if (pending.size() >= hdr) {
                if (hdr == 4) {
                    len = (static_cast<unsigned char>(pending[2]) << 8) |
                          static_cast<unsigned char>(pending[3]);
                } else if (hdr == 10) {
                    len = 0;
                    for (int i = 0; i < 8; ++i)
                        len = (len << 8) | static_cast<unsigned char>(pending[2 + i]);
                }
                if (len > 4 * 1024 * 1024) return FrameState::Error;
                std::size_t total = hdr + (masked ? 4 : 0) + static_cast<std::size_t>(len);
                if (pending.size() >= total) {
                    std::size_t data_off = hdr + (masked ? 4 : 0);
                    payload.assign(pending.data() + data_off, static_cast<std::size_t>(len));
                    if (masked) {
                        const unsigned char* mask =
                            reinterpret_cast<const unsigned char*>(pending.data() + hdr);
                        for (std::size_t i = 0; i < payload.size(); ++i)
                            payload[i] = static_cast<char>(payload[i] ^ mask[i % 4]);
                    }
                    pending.erase(0, total);
                    opcode = b0 & 0x0F;
                    return FrameState::Ok;
                }
            }
        }

        char buf[kChunk];
        net::IoResult result = net::IoResult::Error;
        int n = net::tls_read(ssl, fd, buf, static_cast<int>(sizeof(buf)), result);
        if (n > 0) {
            pending.append(buf, static_cast<std::size_t>(n));
        } else if (result == net::IoResult::WouldBlock) {
            // TLS can hold decrypted bytes that never raise a socket event.
            if (net::tls_pending(ssl) > 0) continue;
            return FrameState::NeedMore;
        } else {
            return FrameState::Closed;
        }
        if (pending.size() > 4 * 1024 * 1024) return FrameState::Error;
    }
}

// Outbound abstraction: either a plain system socket or a connection carried
// inside the userspace WireGuard tunnel (WARP).
struct Outbound {
    socket_t fd = net::kInvalid;
#ifdef BPB_WSX_WG_STACK
    // warp-built-in carries the connection inside its own lwIP stack.
    std::unique_ptr<net::WgConnection> wg;
#endif

    bool valid() const {
        return fd != net::kInvalid
#ifdef BPB_WSX_WG_STACK
               || wg != nullptr
#endif
            ;
    }
#ifdef BPB_WSX_WG_STACK
    bool viaWarp() const { return wg != nullptr; }
#else
    bool viaWarp() const { return false; }
#endif

    // Reads up to len bytes. Returns >0, 0 on timeout, -1 on close.
    int read(char* buf, int len, int timeout_ms) {
#ifdef BPB_WSX_WG_STACK
        if (wg) return wg->read(buf, len, timeout_ms);
#endif
        int n = static_cast<int>(::recv(fd, buf, len, 0));
        if (n > 0) return n;
        if (n == 0) return -1;
        if (net::would_block(net::last_error())) return 0;
        return -1;
    }
    bool write(const char* buf, std::size_t len) {
#ifdef BPB_WSX_WG_STACK
        if (wg) return wg->write(buf, static_cast<int>(len)) == static_cast<int>(len);
#endif
        return send_all(nullptr, fd, buf, len);
    }
    void close() {
#ifdef BPB_WSX_WG_STACK
        if (wg) { wg->close(); wg.reset(); }
#endif
        if (fd != net::kInvalid) { net::close(fd); fd = net::kInvalid; }
    }
};

inline socket_t connect_tcp(const std::string& host, int port, int timeout_ms) {
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

// Connects to host:port, preferring the WARP tunnel when it is ready.
inline Outbound connect_outbound(const std::string& host, int port, int timeout_ms) {
    Outbound ob;
#ifdef BPB_WSX_WG_STACK
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
#elif defined(BPB_WSX_WARP_PROC)
    // The sidecar resolves the name inside the tunnel, so no DNS query leaks.
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
    // Set when parsing stopped only because more bytes are needed; early data
    // often ends mid-address.
    bool need_more = false;
};

// Parses atyp + address starting at pos (no port). Returns false when incomplete.
inline bool parse_atyp_addr(const std::string& buf, std::size_t& pos, Addr& addr) {
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

inline bool read_port(const std::string& buf, std::size_t& pos, Addr& addr) {
    if (pos + 2 > buf.size()) return false;
    addr.port = (static_cast<unsigned char>(buf[pos]) << 8) | static_cast<unsigned char>(buf[pos + 1]);
    pos += 2;
    return true;
}

inline bool resolve_target(const std::string& host, int port, const bpb::proxy::SessionConfig& config,
                           Addr& out) {
    if (config.proxy_ip_mode == "proxyip" && !config.proxy_ips.empty()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<std::size_t> dist(0, config.proxy_ips.size() - 1);
        std::string proxy = config.proxy_ips[dist(gen)];
        auto split_colon = [](const std::string& s) {
            std::vector<std::string> parts;
            std::size_t start = 0;
            while (true) {
                std::size_t at = s.find(':', start);
                if (at == std::string::npos) { parts.push_back(s.substr(start)); break; }
                parts.push_back(s.substr(start, at - start));
                start = at + 1;
            }
            return parts;
        };
        auto parts = split_colon(proxy);
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

// Xray's "ed" (early data) optimisation carries the first stream bytes in the
// Sec-WebSocket-Protocol request header, base64url without padding. Mirrors
// transport/internet/websocket/hub.go: standard base64 (+ / =) is normalised
// first, so both encodings are accepted.
inline std::string decode_early_data(const std::string& b64url) {
    std::string in;
    in.reserve(b64url.size());
    for (char ch : b64url) {
        if (ch == '=') continue;
        if (ch == '+') in.push_back('-');
        else if (ch == '/') in.push_back('_');
        else in.push_back(ch);
    }
    const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int rev[256];
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    for (int i = 0; i < 64; ++i) rev[static_cast<unsigned char>(tbl[i])] = i;
    std::string out;
    int buf = 0, bits = 0;
    for (char ch : in) {
        int v = rev[static_cast<unsigned char>(ch)];
        if (v < 0) return {};   // genuinely not base64: no early data
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

} // namespace bpb::proxy::wsx
