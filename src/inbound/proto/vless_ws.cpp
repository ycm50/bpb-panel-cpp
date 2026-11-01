#include "inbound/inbound.h"

#include "proxy/session.h"
#include "crypto/crypto.h"
#include "net/tls.h"
#include "net/wg_outbound.h"
#include "net/wg_stack.h"
#include "util/log.h"
#include "util/util.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <random>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace bpb::proxy {

namespace {

constexpr std::size_t kChunk = 16384;
using net::socket_t;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool send_all(SSL* ssl, socket_t fd, const char* data, std::size_t len) {
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
            // A partially written websocket frame MUST be finished: bailing out
            // half-way tears the stream and the caller closes the origin, which
            // is exactly the "up=80 down=3380 then upstream closed" signature.
            // Wait for writability in bounded slices and keep retrying for a
            // while; only a truly stuck peer (TCP zero window for 10s) is
            // treated as a dead connection.
            net::PollFd pfd{fd, net::kWrite, 0};
            if (net::poll_fds(&pfd, 1, 500) <= 0) {
                if (++stalls > 20) return false;   // ~10s of no progress
                continue;
            }
            stalls = 0;
            continue;
        }
        return false;
    }
    return true;
}

bool frame_header(std::string& out, int opcode, std::size_t len) {
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
    return true;
}

bool ws_send(SSL* ssl, socket_t fd, const char* data, std::size_t len, int opcode = 0x2) {
    std::string header;
    frame_header(header, opcode, len);
    if (!send_all(ssl, fd, header.data(), header.size())) return false;
    if (len == 0) return true;
    return send_all(ssl, fd, data, len);
}

// Outbound abstraction: either a plain system socket or a connection carried
// inside the userspace WireGuard tunnel (WARP). Callers pick per connection.
struct Outbound {
    socket_t fd = net::kInvalid;
    std::unique_ptr<net::WgConnection> wg;

    bool valid() const { return fd != net::kInvalid || wg != nullptr; }
    bool viaWarp() const { return wg != nullptr; }

    // Reads up to len bytes. Returns >0, 0 on timeout, -1 on close.
    int read(char* buf, int len, int timeout_ms) {
        if (wg) return wg->read(buf, len, timeout_ms);
        int n = static_cast<int>(::recv(fd, buf, len, 0));
        if (n > 0) return n;
        if (n == 0) return -1;
        if (net::would_block(net::last_error())) return 0;
        return -1;
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

struct Addr {
    std::string host;
    int port = 0;
    // Set when parsing stopped only because more bytes are needed; early data
    // often ends mid-address.
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
        std::snprintf(ip, sizeof(ip), "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
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

// urgent=true means "not enough bytes yet, wait for more"; false means the
// bytes are wrong and the session must be dropped. Early data routinely
// delivers a truncated header, so the two cases must not be conflated.
bool parse_vless(const std::string& buf, const std::string& uuid, Addr& addr, std::size_t& header_len,
                 std::string& response_header, bool& need_more) {
    need_more = false;
    if (buf.size() < 18) { need_more = true; return false; }
    int version = static_cast<unsigned char>(buf[0]);
    std::string uuid_bytes = buf.substr(1, 16);
    std::string expected;
    if (uuid.find('-') != std::string::npos) {
        std::string clean;
        for (char c : uuid) {
            if (c != '-') clean += c;
        }
        for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
            expected += static_cast<char>(std::stoi(clean.substr(i, 2), nullptr, 16));
        }
    }
    if (!expected.empty() && expected != uuid_bytes) return false;

    std::size_t pos = 17;
    std::size_t addons_len = static_cast<unsigned char>(buf[pos++]);
    if (buf.size() < pos + addons_len + 1) { need_more = true; return false; }
    pos += addons_len;
    int command = static_cast<unsigned char>(buf[pos++]);
    if (command != 1) return false;  // only TCP
    if (pos + 2 > buf.size()) { need_more = true; return false; }
    if (!read_port(buf, pos, addr)) return false;
    if (!parse_atyp_addr(buf, pos, addr)) { need_more = addr.need_more; return false; }
    header_len = pos;

    response_header.push_back(static_cast<char>(version));
    response_header.push_back(0);
    return true;
}

// Reads one websocket frame payload into out. Returns false on close/error.
//   Ok       -- a whole frame was decoded
//   NeedMore -- no complete frame yet; the caller must poll and retry
enum class FrameState { Ok, Closed, Error, NeedMore };

FrameState read_frame(SSL* ssl, socket_t fd, std::string& pending, std::string& payload,
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
            // TLS can hold decrypted bytes that never trigger a socket readable event.
            if (net::tls_pending(ssl) > 0) continue;
            // Nothing buffered: return to the caller instead of sleeping here.
            // Blocking inside read_frame meant the reverse direction (origin ->
            // eyeball) got no service until a full websocket frame arrived,
            // which is what froze large downloads mid-flight.
            return FrameState::NeedMore;
        } else {
            return FrameState::Closed;
        }
        if (pending.size() > 4 * 1024 * 1024) return FrameState::Error;
    }
}

struct Peer {
    socket_t fd = net::kInvalid;
    std::string in;
};

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

// early holds the bytes Xray delivered in Sec-WebSocket-Protocol; they are
// replayed as the first frame payload so the VLESS handshake sees one
// continuous stream.
void session_loop(SSL* client_ssl, socket_t client, const SessionConfig& config,
                  std::string early = std::string()) {
    Outbound upstream;
    std::string response_header;
    unsigned long long to_upstream = 0;   // WS payload bytes handed to the target
    unsigned long long to_client = 0;     // payload bytes written back to the client
    // Why the loop ended. Every exit path sets this so a stalled session can be
    // diagnosed from the log instead of guessed at.
    // Written by whichever direction ends first; reported once both joined.
    std::atomic<const char*> exitReason{"session finished"};

    bool need_more = false;
    auto try_connect = [&](const std::string& data) -> bool {
        Addr addr;
        std::size_t header_len = 0;
        need_more = false;
        const bool parsed =
            parse_vless(data, config.vl_uuid, addr, header_len, response_header, need_more);
        if (bpb::log::enabled(bpb::log::kTrace)) {
            // Verify the computed header length against the actual bytes: a
            // one-byte over-read silently eats the first payload byte, which
            // corrupts a TLS ClientHello but is invisible to plain HTTP.
            std::fprintf(stderr, "[wg] vless parsed=%d header_len=%zu host=%s port=%d first=%zu:",
                         parsed ? 1 : 0, header_len, addr.host.c_str(), addr.port,
                         data.size() < 40 ? data.size() : 40);
            for (std::size_t i = 0; i < data.size() && i < 40; ++i)
                std::fprintf(stderr, " %02x", static_cast<unsigned char>(data[i]));
            std::fprintf(stderr, "\n");
        }
        if (!parsed) return false;

        Addr target;
        resolve_target(addr.host, addr.port, config, target);
        upstream = connect_outbound(target.host, target.port, 8000);
        if (!upstream.valid()) return false;

        if (!response_header.empty()) {
            if (!ws_send(client_ssl, client, response_header.data(), response_header.size())) return false;
        }
        if (data.size() > header_len) {
            std::string rest = data.substr(header_len);
            const bool wrote = upstream.write(rest.data(), rest.size());
            if (bpb::log::enabled(bpb::log::kTrace)) {
                std::fprintf(stderr, "[wg] initial payload %zu bytes wrote=%d head=", rest.size(),
                             wrote ? 1 : 0);
                for (std::size_t i = 0; i < rest.size() && i < 8; ++i)
                    std::fprintf(stderr, "%02x ", static_cast<unsigned char>(rest[i]));
                std::fprintf(stderr, "\n");
            }
            if (!wrote) return false;
        } else if (bpb::log::enabled(bpb::log::kTrace)) {
            std::fprintf(stderr, "[wg] initial payload empty (header only, %zu bytes)\n",
                         data.size());
        }
        return true;
    };

    // Mirrors cloudflared's stream.Pipe: one blocking transfer per direction.
    //
    // The single-threaded poll loop this replaces had to hand-schedule both
    // directions, and every attempt to tune it (poll timeout, backlog flags,
    // partial reads) only shifted the failure rate: a slow or momentarily
    // unwritable peer in one direction starved the other and the edge gave up
    // 15s later. Two threads cannot starve each other by construction.
    std::atomic<bool> finished{false};
    std::atomic<bool> upstreamReady{false};
    std::mutex upstreamMutex;
    // Byte-level trace counter, only used when --log trace is on.
    int wg_trace_n = 0;

    // ---- client -> upstream ------------------------------------------------
    // Also owns the VLESS handshake: the target address only becomes known once
    // the first websocket frame (or early data) has been parsed.
    std::thread toUpstream([&] {
        std::string hasBuf = early;
        std::string framePending;
        try {
            while (!finished.load()) {
                if (!upstreamReady.load()) {
                    if (!hasBuf.empty()) {
                        bool ok = false;
                        {
                            std::lock_guard<std::mutex> lk(upstreamMutex);
                            ok = try_connect(hasBuf);
                        }
                        if (ok) {
                            hasBuf.clear();
                            upstreamReady.store(true);
                        } else if (!need_more || hasBuf.size() > 8192) {
                            exitReason = "handshake rejected";
                            break;
                        }
                    }
                }
                std::string payload;
                int opcode = 0;
                FrameState st = read_frame(client_ssl, client, framePending, payload, opcode);
                if (st == FrameState::NeedMore) {
                    // Nothing complete yet; a short sleep keeps this thread from
                    // spinning while the other direction keeps flowing.
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                if (st != FrameState::Ok) {
                    exitReason = (st == FrameState::Closed) ? "client closed" : "client frame error";
                    break;
                }
                if (opcode == 0x8) { exitReason = "ws close frame"; break; }
                if (opcode == 0x9) {
                    ws_send(client_ssl, client, payload.data(), payload.size(), 0xA);
                    continue;
                }
                if (opcode == 0xA) continue;

                if (!upstreamReady.load()) {
                    hasBuf += payload;
                    if (hasBuf.size() > 8192) { exitReason = "handshake buffer overflow"; break; }
                    continue;
                }
                if (!payload.empty()) {
                    // No lock: this thread is the only writer. Sharing one mutex
                    // with the download thread let its 100 ms read poll (which
                    // re-acquires immediately) starve this direction for seconds,
                    // so the client's request sat unforwarded while the server
                    // waited - the "handshake fine, response never arrives" bug.
                    if (!upstream.write(payload.data(), payload.size())) {
                        exitReason = "upstream write failed";
                        break;
                    }
                    to_upstream += payload.size();
                    if (bpb::log::enabled(bpb::log::kTrace) && wg_trace_n < 40) {
                        wg_trace_n++;
                        std::fprintf(stderr, "[wg %lld] up %zu:",
                                     (long long)(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                     std::chrono::steady_clock::now().time_since_epoch())
                                                     .count() % 1000000),
                                     payload.size());
                        for (std::size_t i = 0; i < payload.size() && i < 12; ++i)
                            std::fprintf(stderr, " %02x", static_cast<unsigned char>(payload[i]));
                        std::fprintf(stderr, "\n");
                    }
                }
            }
        } catch (...) {
            exitReason = "exception in upload thread";
        }
        finished.store(true);
    });

    // ---- upstream -> client ------------------------------------------------
    std::thread toClient([&] {
        try {
            while (!finished.load()) {
                if (!upstreamReady.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                char buf[kChunk];
                // No lock: this thread is the only reader. Holding it across a
                // blocking read starved the upload direction.
                int n = upstream.read(buf, sizeof(buf), 100);
                if (n < 0) { exitReason = "upstream closed"; break; }
                if (n == 0) continue;
                {
                    if (!ws_send(client_ssl, client, buf, static_cast<std::size_t>(n))) {
                        exitReason = "client write failed";
                        break;
                    }
                    to_client += static_cast<unsigned long long>(n);
                    // Timestamp AFTER the write, so the log measures delivery to
                    // the client rather than just the read from the tunnel.
                    if (bpb::log::enabled(bpb::log::kTrace) && wg_trace_n < 80) {
                        wg_trace_n++;
                        std::fprintf(stderr, "[wg %lld] delivered %d:",
                                     (long long)(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                     std::chrono::steady_clock::now().time_since_epoch())
                                                     .count() % 1000000),
                                     n);
                        for (int i = 0; i < n && i < 12; ++i)
                            std::fprintf(stderr, " %02x", static_cast<unsigned char>(buf[i]));
                        std::fprintf(stderr, "\n");
                    }
                }
            }
        } catch (...) {
            exitReason = "exception in download thread";
        }
        finished.store(true);
    });

    // Join both. Whichever thread stops first sets `finished`, and the other
    // notices it on its next iteration: the client read is non-blocking and the
    // upstream read is capped at 100 ms, so neither can hang the session.
    toUpstream.join();
    finished.store(true);
    toClient.join();

    if (bpb::log::enabled(bpb::log::kDebug))
        std::fprintf(stderr, "[ws] session end: up=%llu down=%llu reason=%s\n", to_upstream,
                     to_client, exitReason.load());
    upstream.close();

    // Close the websocket properly (RFC 6455 5.5.1: opcode 0x8). Dropping the
    // TCP connection without this makes the peer report "close 1006 (abnormal
    // closure): unexpected EOF" even when every payload byte was delivered --
    // the data is fine, the shutdown looks like a crash.
    if (client_ssl || client != net::kInvalid) {
        // Payload = 2-byte big-endian status code 1000 (normal closure).
        // Sending an empty payload yields 1005 ("no status") on the peer, which
        // xray logs at Info level as a failed transfer even though the data was
        // complete; 1000 is the correct, quiet form.
        const unsigned char closeFrame[4] = {0x88, 0x02, 0x03, 0xE8};
        send_all(client_ssl, client, reinterpret_cast<const char*>(closeFrame), sizeof(closeFrame));
    }
    if (client_ssl) {
        SSL_shutdown(client_ssl);
        net::tls_free(client_ssl);
    }
    if (client != net::kInvalid) net::close(client);
}

} // namespace

// Xray's "ed" (early data) optimisation sends the first bytes of the stream in
// the Sec-WebSocket-Protocol request header, base64url without padding, so the
// VLESS handshake can start without waiting for a round trip. Mirrors
// transport/internet/websocket/hub.go: decode with RawURLEncoding and echo the
// original string back on the 101 so the client knows it was understood.
std::string decode_early_data(const std::string& b64url) {
    // Xray normalises the header before decoding, so a client may legitimately
    // send standard base64 (+ / =) as well as base64url. hub.go:
    //   var replacer = strings.NewReplacer("+","-", "/","_", "=","")
    // Rejecting '=' silently disabled early data for such clients.
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

// Entry point for this protocol. The dispatcher (src/inbound/registry.cpp) has
// already matched the "/vl" segment and refused everything else, so the path is
// only interesting for protocol specific parameters; the path itself carries no
// secret -- the VLESS UUID is the credential.
void vless_serve(net::socket_t client_fd, SSL* client_ssl, std::string accept_key,
                 std::string path, std::string ws_protocol, SessionConfig config) {
    (void)path;
    std::string early = ws_protocol.empty() ? std::string() : decode_early_data(ws_protocol);
    std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n";
    // cloudflared's AckConnection only emits Sec-Websocket-Accept when the
    // request actually carried a key (NewResponseHeader hashes it). The tunnel
    // edge does not forward one, so accept_key is meaningless here and must not
    // be advertised.
    if (!accept_key.empty()) response += "Sec-WebSocket-Accept: " + accept_key + "\r\n";
    // Echo the header only when the client sent usable early data, exactly as
    // Xray does; otherwise the client would think its padding was accepted.
    if (!early.empty()) response += "Sec-WebSocket-Protocol: " + ws_protocol + "\r\n";
    response += "\r\n";
    if (!send_all(client_ssl, client_fd, response.data(), response.size())) {
        if (client_ssl) net::tls_free(client_ssl);
        net::close(client_fd);
        return;
    }
    std::thread([client_fd, client_ssl, config, early]() {
        session_loop(client_ssl, client_fd, config, early);
    }).detach();
}

} // namespace bpb::proxy

// Registered by src/inbound/registry.cpp when -DBPB_INBOUNDS includes vless.
namespace bpb::inbound {
// extern: a plain `const` at namespace scope has internal linkage in C++, so
// registry.cpp would not see it.
extern const Inbound vless_inbound = {"vless", "vl", "VLESS", &::bpb::proxy::vless_serve};
} // namespace bpb::inbound