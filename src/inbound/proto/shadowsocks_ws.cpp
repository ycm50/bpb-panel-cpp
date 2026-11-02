#include "inbound/inbound.h"

#include "net/net.h"
#include "net/tls.h"
#include "net/wg_outbound.h"
#include "net/wg_stack.h"
#include "util/log.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <cstdint>
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

// Shadowsocks (SIP004 AEAD) inbound, WebSocket wrapped.
//
// Wire format, per direction:
//
//     salt            keylen bytes, random, fresh per connection
//     chunk*          [AEAD(len, 2 byte BE)] [AEAD(payload)]
//
// subkey = HKDF-SHA1(master_key, salt, "ss-subkey", keylen) and the nonce is
// a 12 byte little-endian counter bumped for every AEAD operation (the length
// and the payload of one chunk use two consecutive nonces). The first payload
// chunk starts with the SOCKS5 style target address, then the data.
//
// The credential is the panel UUID, used verbatim as the password, and the
// method is fixed to aes-256-gcm: SIP004 with OpenSSL AEADs needs no extra
// dependency, and that is the method every client still supports.

namespace bpb::proxy {
namespace {

constexpr std::size_t kChunk = 16384;
constexpr std::size_t kMaxPayload = 0x3FFF;
constexpr std::size_t kTagLen = 16;
constexpr std::size_t kKeyLen = 32;   // aes-256-gcm
constexpr std::size_t kNonceLen = 12;

// Same contract as trojan's send_all: a frame is either written completely or
// the connection is dead. Returning false on WouldBlock (the old behaviour)
// truncated every download once the peer's receive window filled.
constexpr int kSendStallMs = 60000;

// One poll() slice per direction. Idle cost is 10 wake-ups/second/session
// instead of the 1000 the 1 ms sleep this replaces produced.
constexpr int kWaitSliceMs = 100;

// A websocket that upgrades and then never sends its salt keeps a thread and an
// fd for ever (a browser or a scanner poking /ss is enough). The salt is sent
// immediately by every real client, so this only ever catches dead sockets.
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

bool send_all_raw(SSL* ssl, net::socket_t fd, const char* data, std::size_t len) {
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
        net::PollFd pfd{fd, net::kWrite, 0};
        if (net::poll_fds(&pfd, 1, 500) <= 0) {
            stalled_ms += 500;
            if (stalled_ms > kSendStallMs) return false;
            continue;
        }
        stalled_ms = 0;
    }
    return true;
}

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
// --- websocket framing ------------------------------------------------------
//
// The Shadowsocks stream travels inside WebSocket binary frames. Everything
// above the framing layer (salt, chunk lengths, AEAD) is a plain byte stream,
// so this layer only moves bytes in and out of frames.

bool ws_send(SSL* ssl, net::socket_t fd, const char* data, std::size_t len) {
    char head[10];
    std::size_t head_len = 0;
    head[head_len++] = static_cast<char>(0x82);  // FIN + binary
    if (len < 126) {
        head[head_len++] = static_cast<char>(len);
    } else if (len < 65536) {
        head[head_len++] = static_cast<char>(126);
        head[head_len++] = static_cast<char>((len >> 8) & 0xFF);
        head[head_len++] = static_cast<char>(len & 0xFF);
    } else {
        head[head_len++] = static_cast<char>(127);
        for (int i = 7; i >= 0; --i) head[head_len++] = static_cast<char>((len >> (i * 8)) & 0xFF);
    }
    if (!send_all_raw(ssl, fd, head, head_len)) return false;
    return len == 0 || send_all_raw(ssl, fd, data, len);
}

// Decodes client->server frames into a plain byte stream. Control frames are
// answered here so a ping in the middle of a transfer is not mistaken for EOF.
struct WsBytes {
    SSL* ssl = nullptr;
    net::socket_t fd = net::kInvalid;
    std::string raw;

    bool read(std::string& out, int timeout_ms) {
        char buf[kChunk];
        const int n = read_some(ssl, fd, buf, static_cast<int>(sizeof(buf)), timeout_ms);
        if (n < 0) return false;
        if (n > 0) raw.append(buf, static_cast<std::size_t>(n));
        for (;;) {
            if (raw.size() < 2) return true;
            const unsigned char b0 = static_cast<unsigned char>(raw[0]);
            const unsigned char b1 = static_cast<unsigned char>(raw[1]);
            const int opcode = b0 & 0x0F;
            const bool masked = (b1 & 0x80) != 0;
            std::uint64_t len = b1 & 0x7F;
            std::size_t off = 2;
            if (len == 126) {
                if (raw.size() < 4) return true;
                len = (static_cast<unsigned char>(raw[2]) << 8) | static_cast<unsigned char>(raw[3]);
                off = 4;
            } else if (len == 127) {
                if (raw.size() < 10) return true;
                len = 0;
                for (int i = 0; i < 8; ++i) len = (len << 8) | static_cast<unsigned char>(raw[2 + i]);
                off = 10;
            }
            unsigned char mask[4] = {0, 0, 0, 0};
            if (masked) {
                if (raw.size() < off + 4) return true;
                std::memcpy(mask, raw.data() + off, 4);
                off += 4;
            }
            if (raw.size() < off + len) return true;
            std::string body = raw.substr(off, static_cast<std::size_t>(len));
            raw.erase(0, off + static_cast<std::size_t>(len));
            if (masked) {
                for (std::size_t i = 0; i < body.size(); ++i) {
                    body[i] = static_cast<char>(body[i] ^ mask[i & 3]);
                }
            }
            if (opcode == 0x8) return false;
            if (opcode == 0x9) {
                const char pong[2] = {static_cast<char>(0x8A), static_cast<char>(body.size() & 0x7F)};
                send_all_raw(ssl, fd, pong, 2);
                send_all_raw(ssl, fd, body.data(), body.size());
                continue;
            }
            if (opcode == 0xA) continue;
            out += body;
        }
    }
};

// --- SIP004 crypto ----------------------------------------------------------

std::string master_key(const std::string& password) {
    unsigned char key[EVP_MAX_KEY_LENGTH];
    std::memset(key, 0, sizeof(key));
    // SIP004 derives the master key with EVP_BytesToKey(MD5, no salt, 1 round).
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), nullptr,
                   reinterpret_cast<const unsigned char*>(password.data()),
                   static_cast<int>(password.size()), 1, key, nullptr);
    return std::string(reinterpret_cast<char*>(key), kKeyLen);
}

// HKDF-SHA1(key, salt, "ss-subkey", kKeyLen). Done by hand: the EVP_KDF API
// differs between OpenSSL 1.1 and 3.0, and HMAC() is identical in both.
std::string hkdf_sha1(const std::string& key, const std::string& salt) {
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;
    HMAC(EVP_sha1(), salt.data(), static_cast<int>(salt.size()),
         reinterpret_cast<const unsigned char*>(key.data()), key.size(), prk, &prk_len);

    std::string out;
    std::string block;
    unsigned char counter = 1;
    while (out.size() < kKeyLen) {
        std::string msg = block;
        msg += "ss-subkey";
        msg.push_back(static_cast<char>(counter));
        unsigned char mac[EVP_MAX_MD_SIZE];
        unsigned int mac_len = 0;
        HMAC(EVP_sha1(), prk, static_cast<int>(prk_len),
             reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), mac, &mac_len);
        block.assign(reinterpret_cast<char*>(mac), mac_len);
        out += block;
        ++counter;
    }
    out.resize(kKeyLen);
    return out;
}

// One direction of an AEAD connection: its own subkey, its own nonce counter.
class Aead {
public:
    ~Aead() { if (ctx_) EVP_CIPHER_CTX_free(ctx_); }
    Aead() = default;
    Aead(const Aead&) = delete;
    Aead& operator=(const Aead&) = delete;

    bool init(const std::string& master, const std::string& salt) {
        subkey_ = hkdf_sha1(master, salt);
        ctx_ = EVP_CIPHER_CTX_new();
        std::memset(nonce_, 0, sizeof(nonce_));
        return ctx_ != nullptr;
    }

    // in-place API: caller passes the plaintext/ciphertext and gets the other.
    std::string seal(const char* in, std::size_t len) {
        unsigned char buf[kChunk + 64];
        int outl = 0;
        int fin = 0;
        EVP_EncryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr,
                           reinterpret_cast<const unsigned char*>(subkey_.data()), nonce_);
        EVP_EncryptUpdate(ctx_, buf, &outl, reinterpret_cast<const unsigned char*>(in),
                          static_cast<int>(len));
        EVP_EncryptFinal_ex(ctx_, buf + outl, &fin);
        EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG, kTagLen, buf + outl + fin);
        bump();
        return std::string(reinterpret_cast<char*>(buf),
                           static_cast<std::size_t>(outl + fin) + kTagLen);
    }

    // Returns false when the tag does not verify (wrong password or garbage).
    bool open(const char* in, std::size_t len, std::string& out) {
        if (len < kTagLen) return false;
        unsigned char tag[kTagLen];
        std::memcpy(tag, in + len - kTagLen, kTagLen);
        unsigned char buf[kChunk + 64];
        int outl = 0;
        int fin = 0;
        EVP_DecryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr,
                           reinterpret_cast<const unsigned char*>(subkey_.data()), nonce_);
        EVP_DecryptUpdate(ctx_, buf, &outl, reinterpret_cast<const unsigned char*>(in),
                          static_cast<int>(len - kTagLen));
        EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, kTagLen, tag);
        if (EVP_DecryptFinal_ex(ctx_, buf + outl, &fin) <= 0) return false;
        bump();
        out.assign(reinterpret_cast<char*>(buf), static_cast<std::size_t>(outl + fin));
        return true;
    }

private:
    void bump() {
        for (std::size_t i = 0; i < kNonceLen; ++i) {
            if (++nonce_[i] != 0) break;
        }
    }

    EVP_CIPHER_CTX* ctx_ = nullptr;
    std::string subkey_;
    unsigned char nonce_[kNonceLen] = {0};
};
// --- outbound ---------------------------------------------------------------

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
        return send_all_raw(nullptr, fd, buf, len);
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
    // Loopback and RFC1918 destinations belong on a direct socket; the tunnel
    // cannot carry them (see inbound::is_local_target).
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

// Decrypting reader for one connection.
struct SsIn {
    SSL* ssl = nullptr;
    net::socket_t fd = net::kInvalid;
    WsBytes ws;         // websocket frames -> bytes
    std::string master;
    std::string raw;    // still encrypted
    std::string plain;  // decrypted, not yet consumed
    std::unique_ptr<Aead> dec;
    bool want_len = true;
    std::size_t want_payload = 0;
    // Absolute deadline for the header handshake; the per-step limits in
    // parse_header are a stall guard, this is the overall cap. max() until the
    // handshake starts so that relay-only reads are never cut short.
    std::chrono::steady_clock::time_point deadline{
        std::chrono::steady_clock::time_point::max()};

    bool pump(int timeout_ms) {
        if (!ws.read(raw, timeout_ms)) return false;
        if (!dec) {
            if (raw.size() < kKeyLen) return true;
            dec = std::make_unique<Aead>();
            if (!dec->init(master, raw.substr(0, kKeyLen))) return false;
            raw.erase(0, kKeyLen);
        }
        for (;;) {
            if (want_len) {
                if (raw.size() < 2 + kTagLen) break;
                std::string lp;
                if (!dec->open(raw.data(), 2 + kTagLen, lp) || lp.size() != 2) {
                    log::debug("[ss] length chunk failed to authenticate");
                    return false;
                }
                raw.erase(0, 2 + kTagLen);
                want_payload = (static_cast<unsigned char>(lp[0]) << 8) |
                               static_cast<unsigned char>(lp[1]);
                if (want_payload == 0 || want_payload > kMaxPayload) return false;
                want_len = false;
            } else {
                if (raw.size() < want_payload + kTagLen) break;
                std::string pl;
                if (!dec->open(raw.data(), want_payload + kTagLen, pl)) return false;
                raw.erase(0, want_payload + kTagLen);
                plain += pl;
                want_len = true;
            }
        }
        return true;
    }
};

// Encrypting writer: sends its own random salt, then the chunks.
struct SsOut {
    SSL* ssl = nullptr;
    net::socket_t fd = net::kInvalid;
    std::string master;
    std::unique_ptr<Aead> enc;

    bool write(const char* data, std::size_t len) {
        if (!enc) {
            unsigned char salt[kKeyLen];
            if (RAND_bytes(salt, static_cast<int>(sizeof(salt))) != 1) return false;
            enc = std::make_unique<Aead>();
            if (!enc->init(master, std::string(reinterpret_cast<char*>(salt), kKeyLen))) return false;
            if (!ws_send(ssl, fd, reinterpret_cast<char*>(salt), kKeyLen)) return false;
        }
        std::size_t off = 0;
        while (off < len) {
            const std::size_t n = (len - off < kMaxPayload) ? (len - off) : kMaxPayload;
            const char lb[2] = {static_cast<char>((n >> 8) & 0xFF),
                                static_cast<char>(n & 0xFF)};
            // One frame per chunk: the length and its payload stay together,
            // which also keeps the frame count down for small writes.
            std::string frame = enc->seal(lb, 2);
            frame += enc->seal(data + off, n);
            if (!ws_send(ssl, fd, frame.data(), frame.size())) return false;
            off += n;
        }
        return true;
    }
};
// Waits until `n` decrypted bytes are buffered, bounded in time: `limit_ms` per
// stall plus in.deadline for the whole handshake, so a peer that dribbles one
// byte at a time cannot keep a thread and an fd forever.
bool ensure(SsIn& in, std::size_t n, int limit_ms) {
    const auto start = std::chrono::steady_clock::now();
    while (in.plain.size() < n) {
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

// The first decrypted bytes are the SOCKS5 style target address.
bool parse_header(SsIn& in, Header& out) {
    in.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeTimeoutMs);
    if (!ensure(in, 1, 10000)) return false;
    std::size_t pos = 0;
    const unsigned char atyp = static_cast<unsigned char>(in.plain[pos++]);
    if (atyp == 0x01) {
        if (!ensure(in, pos + 4, 10000)) return false;
        char ip[32];
        std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                      static_cast<unsigned char>(in.plain[pos]),
                      static_cast<unsigned char>(in.plain[pos + 1]),
                      static_cast<unsigned char>(in.plain[pos + 2]),
                      static_cast<unsigned char>(in.plain[pos + 3]));
        out.host = ip;
        pos += 4;
    } else if (atyp == 0x03) {
        if (!ensure(in, pos + 1, 10000)) return false;
        const std::size_t len = static_cast<unsigned char>(in.plain[pos++]);
        if (!ensure(in, pos + len, 10000)) return false;
        out.host = in.plain.substr(pos, len);
        pos += len;
    } else if (atyp == 0x04) {
        if (!ensure(in, pos + 16, 10000)) return false;
        char ip[64];
        std::snprintf(ip, sizeof(ip),
                      "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
                      static_cast<unsigned char>(in.plain[pos]),
                      static_cast<unsigned char>(in.plain[pos + 1]),
                      static_cast<unsigned char>(in.plain[pos + 2]),
                      static_cast<unsigned char>(in.plain[pos + 3]),
                      static_cast<unsigned char>(in.plain[pos + 4]),
                      static_cast<unsigned char>(in.plain[pos + 5]),
                      static_cast<unsigned char>(in.plain[pos + 6]),
                      static_cast<unsigned char>(in.plain[pos + 7]),
                      static_cast<unsigned char>(in.plain[pos + 8]),
                      static_cast<unsigned char>(in.plain[pos + 9]),
                      static_cast<unsigned char>(in.plain[pos + 10]),
                      static_cast<unsigned char>(in.plain[pos + 11]),
                      static_cast<unsigned char>(in.plain[pos + 12]),
                      static_cast<unsigned char>(in.plain[pos + 13]),
                      static_cast<unsigned char>(in.plain[pos + 14]),
                      static_cast<unsigned char>(in.plain[pos + 15]));
        out.host = ip;
        pos += 16;
    } else {
        log::debug("[ss] unsupported address type %u", static_cast<unsigned>(atyp));
        return false;
    }
    if (!ensure(in, pos + 2, 10000)) return false;
    out.port = (static_cast<unsigned char>(in.plain[pos]) << 8) |
               static_cast<unsigned char>(in.plain[pos + 1]);
    pos += 2;
    out.payload = in.plain.substr(pos);
    in.plain.clear();
    return true;
}

void relay(SSL* ssl, net::socket_t client, Outbound& ob, SsIn& in, SsOut& out,
           const std::string& first) {
    if (!first.empty() && !ob.write(first.data(), first.size())) return;
    std::atomic<bool> stop{false};
    std::thread upstream([&] {
        while (!stop.load()) {
            // pump() blocks in poll() for one slice, so this thread sleeps
            // instead of spinning on recv()/EAGAIN.
            if (!in.pump(kWaitSliceMs)) break;
            if (!in.plain.empty()) {
                const bool ok = ob.write(in.plain.data(), in.plain.size());
                in.plain.clear();
                if (!ok) break;
            }
        }
        stop.store(true);
    });
    char buf[kChunk];
    while (!stop.load()) {
        // read() polls for up to one slice: an idle session costs one wake-up
        // per slice, not a hot loop.
        const int n = ob.read(buf, static_cast<int>(sizeof(buf)), kWaitSliceMs);
        if (n < 0) break;
        if (n > 0 && !out.write(buf, static_cast<std::size_t>(n))) break;
    }
    stop.store(true);
    upstream.join();
    ob.close();
}

void shadowsocks_serve(net::socket_t client, SSL* ssl, std::string accept_key, std::string path,
                       std::string ws_protocol, SessionConfig cfg) {
    (void)path;
    (void)ws_protocol;

    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n";
    if (!accept_key.empty()) response += "Sec-WebSocket-Accept: " + accept_key + "\r\n";
    response += "\r\n";
    if (!send_all_raw(ssl, client, response.data(), response.size())) {
        if (ssl) net::tls_free(ssl);
        net::close(client);
        return;
    }

    // The panel UUID doubles as the Shadowsocks password, like the Trojan
    // inbound: one credential per panel, no extra setting to keep in sync.
    const std::string master = master_key(cfg.vl_uuid);
    std::thread([client, ssl, master] {
        enable_keepalive(client);
        SsIn in;
        in.ssl = ssl;
        in.fd = client;
        in.ws.ssl = ssl;
        in.ws.fd = client;
        in.master = master;
        Header head;
        if (parse_header(in, head)) {
            Outbound ob = connect_outbound(head.host, head.port, 15000);
            if (ob.valid()) {
                log::debug("[ss] %s:%d", head.host.c_str(), head.port);
                SsOut out;
                out.ssl = ssl;
                out.fd = client;
                out.master = master;
                relay(ssl, client, ob, in, out, head.payload);
            }
        }
        if (ssl) net::tls_free(ssl);
        net::close(client);
    }).detach();
}

} // namespace
} // namespace bpb::proxy

// Registered by src/inbound/registry.cpp when -DBPB_INBOUNDS includes shadowsocks.
namespace bpb::inbound {
// extern: a plain const at namespace scope has internal linkage.
extern const Inbound shadowsocks_inbound = {"shadowsocks", "ss", "Shadowsocks",
                                            &::bpb::proxy::shadowsocks_serve};
} // namespace bpb::inbound