#include "tunnel/h2.h"
#include "util/log.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>

namespace bpb::tunnel {

// Frame-level tracing is OPT-IN and off by default. It used to be missing a
// default-off guarantee in one path (the relay's per-iteration tracing), which
// turned a closed flow-control window into tens of thousands of journal lines.
// BPB_TRACE=1 enables everything; BPB_TUNNEL_TRACE=1 is kept for compatibility.
bool h2_trace_enabled() {
    // One switch to rule them: --log trace / BPB_LOG=trace turns on frame
    // tracing, and the historical BPB_TRACE / BPB_TUNNEL_TRACE variables are
    // still honoured so existing debug recipes keep working.
    static const bool on = bpb::log::level() >= bpb::log::kTrace;
    return on;
}

void h2_trace(const char* fmt, ...) {
    if (!h2_trace_enabled()) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "\n");
    std::fflush(stderr);
}

namespace {

constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kPrefaceLen = 24;

enum : std::uint8_t {
    kFrameData = 0x0,
    kFrameHeaders = 0x1,
    kFramePriority = 0x2,
    kFrameRstStream = 0x3,
    kFrameSettings = 0x4,
    kFramePushPromise = 0x5,
    kFramePing = 0x6,
    kFrameGoAway = 0x7,
    kFrameWindowUpdate = 0x8,
    kFrameContinuation = 0x9,
};

enum : std::uint8_t {
    kFlagEndStream = 0x1,
    kFlagAck = 0x1,
    kFlagEndHeaders = 0x4,
    kFlagPadded = 0x8,
    kFlagPriority = 0x20,
};

void put_u32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>((x >> 24) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<std::uint8_t>(x & 0xFF));
}
void put_u24(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<std::uint8_t>(x & 0xFF));
}

// ---- HPACK (decoder subset + encoder for our responses) -------------------

struct HpackTable {
    std::vector<std::pair<std::string, std::string>> dynamic;
    std::size_t size = 0;      // bytes currently used (RFC 7541 s4.1)
    std::size_t maxSize = 4096;
};

const char* kStatic[62][2] = {
    {":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"},
    {":path", "/index.html"}, {":scheme", "http"}, {":scheme", "https"},
    {":status", "200"}, {":status", "204"}, {":status", "206"}, {":status", "304"},
    {":status", "400"}, {":status", "404"}, {":status", "500"},
    {"accept-charset", ""}, {"accept-encoding", "gzip, deflate"}, {"accept-language", ""},
    {"accept-ranges", ""}, {"accept", ""}, {"access-control-allow-origin", ""},
    {"age", ""}, {"allow", ""}, {"authorization", ""}, {"cache-control", ""},
    {"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""},
    {"content-length", ""}, {"content-location", ""}, {"content-range", ""},
    {"content-type", ""}, {"cookie", ""}, {"date", ""}, {"etag", ""}, {"expect", ""},
    {"expires", ""}, {"from", ""}, {"host", ""}, {"if-match", ""},
    {"if-modified-since", ""}, {"if-none-match", ""}, {"if-range", ""},
    {"if-unmodified-since", ""}, {"last-modified", ""}, {"link", ""}, {"location", ""},
    {"max-forwards", ""}, {"proxy-authenticate", ""}, {"proxy-authorization", ""},
    {"range", ""}, {"referer", ""}, {"refresh", ""}, {"retry-after", ""}, {"server", ""},
    {"set-cookie", ""}, {"strict-transport-security", ""}, {"transfer-encoding", ""},
    {"user-agent", ""}, {"vary", ""}, {"via", ""}, {"www-authenticate", ""}};

// ---- HPACK Huffman decoder (RFC 7541 Appendix B) --------------------------
// Table data generated from nghttp2 (MIT licensed).
// HPACK Huffman code table (RFC 7541 Appendix B), from nghttp2 (MIT).
// Index = symbol (0..255), plus EOS at 256.
// HPACK Huffman tables (RFC 7541 Appendix B), generated from nghttp2 (MIT).
#include "tunnel/huff_table.inc"

std::string huffman_decode(const std::uint8_t* data, std::size_t len) {
    std::string out;
    std::uint64_t acc = 0;
    int bits = 0;
    for (std::size_t i = 0; i < len; ++i) {
        acc = (acc << 8) | static_cast<std::uint64_t>(data[i]);
        bits += 8;
        while (bits >= 5) {
            bool matched = false;
            for (int s = 0; s < 256; ++s) {
                int bl = kHuffBits[s];
                if (bl > bits) continue;
                std::uint32_t code = kHuffCodes[s] >> (32 - bl);
                std::uint64_t mask = (bl >= 64) ? ~0ull : ((1ull << bl) - 1);
                std::uint64_t top = (acc >> (bits - bl)) & mask;
                if (top == code) {
                    out.push_back(static_cast<char>(s));
                    bits -= bl;
                    matched = true;
                    break;
                }
            }
            if (!matched) break;
        }
    }
    return out;
}

std::uint32_t read_int(const std::uint8_t* p, std::size_t len, std::size_t& pos, int prefixBits) {
    if (pos >= len) return 0;
    const std::uint32_t mask = (1u << prefixBits) - 1;
    std::uint32_t v = p[pos] & mask;
    ++pos;
    if (v < mask) return v;
    std::uint32_t shift = 0;
    while (pos < len) {
        std::uint8_t b = p[pos++];
        v += static_cast<std::uint32_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return v;
}

std::string read_string(const std::uint8_t* p, std::size_t len, std::size_t& pos) {
    if (pos >= len) return {};
    bool huffman = (p[pos] & 0x80) != 0;
    std::uint32_t n = read_int(p, len, pos, 7);
    if (pos + n > len) return {};
    std::string out;
    if (!huffman) {
        out.assign(reinterpret_cast<const char*>(p + pos), n);
    } else {
        out = huffman_decode(p + pos, n);
    }
    pos += n;
    return out;
}

// Decodes a header block into name/value pairs (best effort, static+dynamic).
// Repeated header fields (set-cookie, etc.) are joined with a comma, matching
// what an HTTP/1 client would see.
void put_header(std::map<std::string, std::string>& out, const std::string& name,
                const std::string& value) {
    auto it = out.find(name);
    if (it == out.end()) {
        out.emplace(name, value);
    } else if (it->second != value) {
        it->second += ", ";
        it->second += value;
    }
}

void hpack_decode(const std::uint8_t* p, std::size_t len, HpackTable& tab,
                  std::map<std::string, std::string>& out) {
    std::size_t pos = 0;
    while (pos < len) {
        std::uint8_t b = p[pos];
        if (b & 0x80) {  // indexed
            std::uint32_t idx = read_int(p, len, pos, 7);
            if (idx == 0) continue;
            if (idx <= 61) {
                put_header(out, kStatic[idx - 1][0], kStatic[idx - 1][1]);
            } else if (idx - 62 < tab.dynamic.size()) {
                auto& e = tab.dynamic[idx - 62];
                put_header(out, e.first, e.second);
            }
        } else if ((b & 0xC0) == 0x40) {  // literal with incremental indexing
            std::uint32_t idx = read_int(p, len, pos, 6);
            std::string name;
            if (idx > 0 && idx <= 61) name = kStatic[idx - 1][0];
            else if (idx > 61 && idx - 62 < tab.dynamic.size()) name = tab.dynamic[idx - 62].first;
            else name = read_string(p, len, pos);
            std::string value = read_string(p, len, pos);
            put_header(out, name, value);
            // RFC 7541 s4.4: insert at the front, then evict from the back
            // until the table fits its size bound.
            const std::size_t entrySize = name.size() + value.size() + 32;
            if (entrySize <= tab.maxSize) {
                tab.dynamic.insert(tab.dynamic.begin(), {name, value});
                tab.size += entrySize;
                while (tab.size > tab.maxSize && !tab.dynamic.empty()) {
                    const auto& last = tab.dynamic.back();
                    tab.size -= last.first.size() + last.second.size() + 32;
                    tab.dynamic.pop_back();
                }
            }
        } else if ((b & 0xF0) == 0x00 || (b & 0xF0) == 0x10) {  // literal without/never indexed
            int prefix = 4;
            std::uint32_t idx = read_int(p, len, pos, prefix);
            std::string name;
            if (idx > 0 && idx <= 61) name = kStatic[idx - 1][0];
            else if (idx > 61 && idx - 62 < tab.dynamic.size()) name = tab.dynamic[idx - 62].first;
            else name = read_string(p, len, pos);
            std::string value = read_string(p, len, pos);
            put_header(out, name, value);
        } else if ((b & 0xE0) == 0x20) {  // dynamic table size update
            tab.maxSize = read_int(p, len, pos, 5);
            while (tab.size > tab.maxSize && !tab.dynamic.empty()) {
                const auto& last = tab.dynamic.back();
                tab.size -= last.first.size() + last.second.size() + 32;
                tab.dynamic.pop_back();
            }
        } else {
            ++pos;
        }
    }
}

// Encoder: literal without indexing, indexed name when in the static table.
int static_index_of(const std::string& name) {
    for (int i = 0; i < 61; ++i)
        if (name == kStatic[i][0]) return i + 1;
    return 0;
}

void hpack_int(std::vector<std::uint8_t>& out, std::uint32_t v, int prefixBits, std::uint8_t first) {
    const std::uint32_t maxP = (1u << prefixBits) - 1;
    if (v < maxP) {
        out.push_back(static_cast<std::uint8_t>(first | v));
        return;
    }
    out.push_back(static_cast<std::uint8_t>(first | maxP));
    v -= maxP;
    while (v >= 128) {
        out.push_back(static_cast<std::uint8_t>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

void hpack_str(std::vector<std::uint8_t>& out, const std::string& s) {
    hpack_int(out, static_cast<std::uint32_t>(s.size()), 7, 0x00);
    out.insert(out.end(), s.begin(), s.end());
}

void hpack_literal(std::vector<std::uint8_t>& out, const std::string& name, const std::string& value) {
    int idx = static_index_of(name);
    if (idx > 0) {
        hpack_int(out, static_cast<std::uint32_t>(idx), 4, 0x00);
    } else {
        out.push_back(0x00);
        hpack_str(out, name);
    }
    hpack_str(out, value);
}

} // namespace

// ---------------------------------------------------------------------------

class H2ServerImpl : public H2Server {
public:
    explicit H2ServerImpl(const Callbacks& cb) : cb_(cb) {}
    ~H2ServerImpl() override { close(); }

    bool connect(const std::string& host, std::uint16_t port, const std::string& sni,
                 int timeout_ms, std::string& error) override;
    bool startHttp2(int timeout_ms, std::string& error) override;
    bool poll(int timeout_ms) override;
    bool write_headers(std::uint32_t streamId, const std::string& status,
                       const std::vector<std::pair<std::string, std::string>>& extra,
                       bool endStream) override;
    bool write_data(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                    bool endStream) override;
    std::size_t write_data_some(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                                bool endStream) override;
    bool send_credit_available(std::uint32_t streamId) override;
    bool write_rst_stream(std::uint32_t streamId, std::uint32_t errorCode) override;
    void close() override;

private:
    // Blocks until the connection-level AND stream-level send windows can take
    // at least one byte, consuming frames that arrive meanwhile.
    bool await_send_window(std::uint32_t streamId, int timeout_ms);
    void apply_settings(const std::uint8_t* payload, std::size_t len);
    // Emits at most one "waiting for credit" line per stream per second.
    void trace_credit_wait(std::uint32_t streamId, std::int64_t sw, std::size_t pending);
    void deliver_request(std::uint32_t streamId, std::uint8_t flags);
    bool send_all(const void* data, std::size_t len);
    bool recv_exact(void* buf, std::size_t len);
    bool send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                    const std::uint8_t* payload, std::size_t len);
    // 1 = a frame was decoded, 0 = the timeout expired, -1 = the connection is
    // unusable (peer closed, TLS error, socket error). The three states must be
    // distinguished: the old bool collapsed "timeout" and "dead" into one value,
    // so a vanished edge made poll() spin forever instead of triggering a
    // reconnect.
    int read_frame(int timeout_ms, std::uint8_t& type, std::uint8_t& flags,
                   std::uint32_t& streamId, std::vector<std::uint8_t>& payload);
    void dispatch(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                  const std::uint8_t* payload, std::size_t len);

    Callbacks cb_;
    int fd_ = -1;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    HpackTable reqTable_;
    bool started_ = false;
    bool closed_ = false;
    // Set by read_frame/send paths when the transport is gone. Survives into
    // poll()/write_data() so every caller can see "this connection is dead"
    // without having to inspect errno.
    bool fatal_ = false;
    std::string fatalReason_;

    // --- HTTP/2 flow control (RFC 7540 s6.9) -------------------------------
    // The edge's SETTINGS_INITIAL_WINDOW_SIZE governs *our* send window on each
    // stream; the connection window starts at the protocol default 65535 and is
    // only raised by WINDOW_UPDATE. Without tracking these we would happily push
    // a long-lived WebSocket past 64 KiB and get the stream reset.
    // RFC 7540 s6.9.1: a flow-control window must never exceed 2^31-1.
    static constexpr std::int64_t kMaxWindow = 0x7FFFFFFF;
    std::int64_t connSendWindow_ = 65535;
    std::map<std::uint32_t, std::int64_t> streamSendWindow_;
    std::int64_t peerInitialWindow_ = 65535;
    std::map<std::uint32_t, std::chrono::steady_clock::time_point> creditWaitLast_;
    // Streams the edge has reset. Writing DATA on them is a protocol violation
    // and gets the connection killed, so remember them for the stream's life.
    std::set<std::uint32_t> resetStreams_;

    // The HEADERS block being assembled across CONTINUATION frames.
    std::uint32_t contStream_ = 0;
    std::vector<std::uint8_t> contBlock_;
};

bool H2ServerImpl::send_all(const void* data, std::size_t len) {
    const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
    std::size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl_, p + off, static_cast<int>(len - off));
        if (n <= 0) {
            int e = SSL_get_error(ssl_, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                pollfd pfd{fd_, static_cast<short>(e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0};
                ::poll(&pfd, 1, 5000);
                continue;
            }
            fatal_ = true;
            fatalReason_ = "tls write failed";
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

bool H2ServerImpl::recv_exact(void* buf, std::size_t len) {
    std::uint8_t* p = static_cast<std::uint8_t*>(buf);
    std::size_t off = 0;
    while (off < len) {
        int n = SSL_read(ssl_, p + off, static_cast<int>(len - off));
        if (n <= 0) {
            int e = SSL_get_error(ssl_, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                pollfd pfd{fd_, static_cast<short>(e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0};
                int pr = ::poll(&pfd, 1, 5000);
                if (pr <= 0) {
                    // A stalled TLS read is a dead path, not a slow peer: the
                    // edge sends PING/GOAWAY long before five seconds.
                    fatal_ = true;
                    fatalReason_ = "tls read stalled";
                    return false;
                }
                continue;
            }
            fatal_ = true;
            fatalReason_ = (e == SSL_ERROR_ZERO_RETURN) ? "peer closed (tls)"
                                                        : "tls read failed";
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

bool H2ServerImpl::send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                              const std::uint8_t* payload, std::size_t len) {
    static const char* names[] = {"DATA", "HEADERS", "PRIORITY", "RST", "SETTINGS",
                                  "PUSH", "PING", "GOAWAY", "WINDOW_UPDATE", "CONT"};
    h2_trace("[h2 tx] %s flags=0x%02x stream=%u len=%zu",
             type < 10 ? names[type] : "?", flags, streamId, len);
    std::vector<std::uint8_t> hdr;
    hdr.reserve(9);
    put_u24(hdr, static_cast<std::uint32_t>(len));
    hdr.push_back(type);
    hdr.push_back(flags);
    put_u32(hdr, streamId & 0x7FFFFFFF);
    if (!send_all(hdr.data(), hdr.size())) return false;
    if (len && !send_all(payload, len)) return false;
    return true;
}

bool H2ServerImpl::connect(const std::string& host, std::uint16_t port, const std::string& sni,
                           int timeout_ms, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string ps = std::to_string(port);
    if (getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || !res) {
        error = "resolve failed: " + host;
        return false;
    }
    fd_ = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        if (::connect(s, p->ai_addr, p->ai_addrlen) == 0) {
            fd_ = s;
            break;
        }
        ::close(s);
    }
    freeaddrinfo(res);
    if (fd_ < 0) {
        error = "tcp connect failed";
        return false;
    }
    int one = 1;
    setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    // cloudflared dials the edge with a plain net.Dialer, which enables TCP
    // keepalive (15s) by default; it never sends application-level h2 PINGs.
    // Match that so a silently dead path is detected by the kernel rather than
    // waiting for the next write to fail.
    setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
    int idle = 15, intvl = 15, cnt = 4;
    setsockopt(fd_, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd_, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd_, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif

    SSL_library_init();
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) {
        error = "SSL_CTX_new failed";
        return false;
    }
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    // Honour the standard SSLKEYLOGFILE so a capture of this connection can be
    // decrypted offline (Wireshark: Preferences -> Protocols -> TLS). Only used
    // for diagnostics; absent the variable nothing is written.
    if (const char* kl = ::getenv("SSLKEYLOGFILE")) {
        if (FILE* kf = ::fopen(kl, "a")) {
            SSL_CTX_set_keylog_callback(ctx_, [](const SSL*, const char* line) {
                if (FILE* f = ::fopen(::getenv("SSLKEYLOGFILE"), "a")) {
                    std::fprintf(f, "%s\n", line);
                    std::fclose(f);
                }
            });
            ::fclose(kf);
        }
    }
    // The edge does not negotiate ALPN; do not request one.
    ssl_ = SSL_new(ctx_);
    SSL_set_fd(ssl_, fd_);
    SSL_set_tlsext_host_name(ssl_, sni.c_str());
    if (SSL_connect(ssl_) != 1) {
        error = std::string("TLS failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }
    return true;
}

bool H2ServerImpl::startHttp2(int timeout_ms, std::string& error) {
    // The edge sends the HTTP/2 client preface first.
    std::uint8_t pre[kPrefaceLen];
    if (!recv_exact(pre, kPrefaceLen)) {
        error = "no HTTP/2 preface from edge";
        return false;
    }
    if (std::memcmp(pre, kPreface, kPrefaceLen) != 0) {
        error = "edge preface mismatch";
        return false;
    }

    // Our SETTINGS (server side).
    std::vector<std::uint8_t> settings;
    // HEADER_TABLE_SIZE = 0. cloudflared's Go client honours this by using an
    // empty dynamic table, which removes an entire class of desynchronisation
    // bugs on a connection that lives for days.
    settings.push_back(0x00);
    settings.push_back(0x01);
    put_u32(settings, 0);
    // MAX_CONCURRENT_STREAMS: the edge multiplexes many eyeball requests.
    settings.push_back(0x00);
    settings.push_back(0x03);
    put_u32(settings, 1000);
    settings.push_back(0x00);
    settings.push_back(0x04);  // INITIAL_WINDOW_SIZE
    put_u32(settings, 16 * 1024 * 1024);
    if (!send_frame(kFrameSettings, 0, 0, settings.data(), settings.size())) {
        error = "send SETTINGS failed";
        return false;
    }

    // Consume the edge's SETTINGS; ACK it.
    std::uint8_t type = 0, flags = 0;
    std::uint32_t sid = 0;
    std::vector<std::uint8_t> payload;
    if (read_frame(timeout_ms, type, flags, sid, payload) != 1) {
        error = fatal_ && !fatalReason_.empty() ? fatalReason_ : "no SETTINGS frames from edge";
        return false;
    }
    dispatch(type, flags, sid, payload.data(), payload.size());
    started_ = true;
    return true;
}

int H2ServerImpl::read_frame(int timeout_ms, std::uint8_t& type, std::uint8_t& flags,
                             std::uint32_t& streamId, std::vector<std::uint8_t>& payload) {
    if (fd_ < 0 || !ssl_ || fatal_) return -1;
    // SSL_pending() must be checked first: a TLS record can already hold the
    // next frame while the socket itself has nothing to report, and poll()
    // would then sleep for the full timeout with the frame sitting in memory.
    if (SSL_pending(ssl_) <= 0) {
        pollfd pfd{fd_, POLLIN, 0};
        int pr = ::poll(&pfd, 1, timeout_ms);
        if (pr == 0) return 0;  // idle, not broken
        if (pr < 0) {
            fatal_ = true;
            fatalReason_ = "poll failed";
            return -1;
        }
        if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
            fatal_ = true;
            fatalReason_ = "socket error";
            return -1;
        }
    }

    std::uint8_t hdr[9];
    if (!recv_exact(hdr, 9)) {
        fatal_ = true;
        if (fatalReason_.empty()) fatalReason_ = "peer closed";
        return -1;
    }
    std::size_t len = (static_cast<std::size_t>(hdr[0]) << 16) |
                      (static_cast<std::size_t>(hdr[1]) << 8) | hdr[2];
    type = hdr[3];
    flags = hdr[4];
    streamId = ((static_cast<std::uint32_t>(hdr[5]) << 24) |
                (static_cast<std::uint32_t>(hdr[6]) << 16) |
                (static_cast<std::uint32_t>(hdr[7]) << 8) | hdr[8]) & 0x7FFFFFFF;
    payload.assign(len, 0);
    if (len && !recv_exact(payload.data(), len)) {
        fatal_ = true;
        if (fatalReason_.empty()) fatalReason_ = "truncated frame";
        return -1;
    }
    return 1;
}

void H2ServerImpl::dispatch(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                            const std::uint8_t* payload, std::size_t len) {
    static const char* names[] = {"DATA", "HEADERS", "PRIORITY", "RST", "SETTINGS",
                                  "PUSH", "PING", "GOAWAY", "WINDOW_UPDATE", "CONT"};
    h2_trace("[h2 rx] %s flags=0x%02x stream=%u len=%zu",
             type < 10 ? names[type] : "?", flags, streamId, len);
    switch (type) {
        case kFrameSettings:
            if (!(flags & kFlagAck)) {
                apply_settings(payload, len);
                send_frame(kFrameSettings, kFlagAck, 0, nullptr, 0);
            }
            break;
        case kFrameHeaders: {
            std::size_t off = 0;
            if (flags & kFlagPadded) off += 1 + payload[0];
            if (flags & kFlagPriority) off += 5;
            if (off > len) break;
            // Accumulate until END_HEADERS: a header block may legally be split
            // across CONTINUATION frames, and decoding a prefix yields garbage.
            contStream_ = streamId;
            contBlock_.assign(payload + off, payload + len);
            if (flags & kFlagEndHeaders) {
                contStream_ = 0;
                deliver_request(streamId, flags);
            }
            break;
        }
        case kFrameContinuation: {
            if (streamId != contStream_) break;  // not ours to assemble
            contBlock_.insert(contBlock_.end(), payload, payload + len);
            if (flags & kFlagEndHeaders) {
                contStream_ = 0;
                deliver_request(streamId, flags);
            }
            break;
        }
        case kFrameRstStream: {
            // The edge gave up on this stream; release its window bookkeeping
            // and let the owner close the origin side. Remember it so the relay
            // cannot send DATA here afterwards (see write_data_some).
            if (len >= 4) {
                const std::uint32_t code = (static_cast<std::uint32_t>(payload[0]) << 24) |
                                           (static_cast<std::uint32_t>(payload[1]) << 16) |
                                           (static_cast<std::uint32_t>(payload[2]) << 8) |
                                           static_cast<std::uint32_t>(payload[3]);
                // 0 NO_ERROR, 1 PROTOCOL_ERROR, 2 INTERNAL_ERROR, 7 REFUSED,
                // 8 CANCEL, 11 ENHANCE_YOUR_CALM (rate limit), 13 INTERNAL
                h2_trace("[h2] RST_STREAM stream=%u code=%u", streamId, code);
            }
            resetStreams_.insert(streamId);
            streamSendWindow_.erase(streamId);
            if (cb_.on_reset) cb_.on_reset(streamId);
            break;
        }
        case kFrameWindowUpdate: {
            if (len < 4) break;
            const std::uint32_t inc = ((static_cast<std::uint32_t>(payload[0]) << 24) |
                                       (static_cast<std::uint32_t>(payload[1]) << 16) |
                                       (static_cast<std::uint32_t>(payload[2]) << 8) |
                                       static_cast<std::uint32_t>(payload[3])) &
                                      0x7FFFFFFF;
            if (streamId == 0) {
                connSendWindow_ += inc;
                // The connection window is a 31-bit counter by definition. Going
                // past that means our accounting has drifted (a credit applied
                // twice), and continuing would silently overrun the peer's real
                // buffer. Treat it as a broken connection and let the supervisor
                // rebuild it rather than shipping garbage downstream.
                if (connSendWindow_ > kMaxWindow) {
                    fatal_ = true;
                    fatalReason_ = "connection window overflow";
                    if (cb_.on_error) cb_.on_error(fatalReason_);
                }
            } else {
                // A stream window of exactly 0 is a LEGAL state: it means the
                // peer has not granted more credit yet. Treating 0 as "not
                // initialised" and reinstating peerInitialWindow_ here invented
                // megabytes of credit that the edge never granted, which then
                // desynchronised the whole connection (observed as sw=0 with a
                // billion-byte connection window, i.e. a permanent stall).
                auto it = streamSendWindow_.find(streamId);
                if (it == streamSendWindow_.end()) {
                    it = streamSendWindow_.emplace(streamId, peerInitialWindow_).first;
                }
                it->second += inc;
                if (it->second > kMaxWindow) {
                    fatal_ = true;
                    fatalReason_ = "stream window overflow";
                    if (cb_.on_error) cb_.on_error(fatalReason_);
                }
            }
            break;
        }
        case kFrameData:
            if (cb_.on_data) cb_.on_data(streamId, payload, len);
            if (flags & kFlagEndStream && cb_.on_end) cb_.on_end(streamId);
            // Keep the edge's send window open.
            if (len) {
                std::vector<std::uint8_t> wu;
                put_u32(wu, static_cast<std::uint32_t>(len));
                send_frame(kFrameWindowUpdate, 0, 0, wu.data(), wu.size());
                send_frame(kFrameWindowUpdate, 0, streamId, wu.data(), wu.size());
            }
            break;
        case kFramePing:
            if (!(flags & kFlagAck)) send_frame(kFramePing, kFlagAck, 0, payload, len);
            break;
        case kFrameGoAway:
            // The edge is retiring this connection; nothing may be started on
            // it any more. Flag it so the supervisor reconnects immediately
            // instead of waiting for the socket to die.
            fatal_ = true;
            fatalReason_ = "GOAWAY from edge";
            if (cb_.on_error) cb_.on_error(fatalReason_);
            break;
        default:
            break;
    }
}

// SETTINGS_INITIAL_WINDOW_SIZE retroactively shifts every stream's send window
// by the delta (RFC 7540 s6.9.2), which is why we keep the peer's value.
void H2ServerImpl::apply_settings(const std::uint8_t* payload, std::size_t len) {
    for (std::size_t off = 0; off + 6 <= len; off += 6) {
        const std::uint16_t id = static_cast<std::uint16_t>((payload[off] << 8) | payload[off + 1]);
        const std::uint32_t v = (static_cast<std::uint32_t>(payload[off + 2]) << 24) |
                                (static_cast<std::uint32_t>(payload[off + 3]) << 16) |
                                (static_cast<std::uint32_t>(payload[off + 4]) << 8) |
                                static_cast<std::uint32_t>(payload[off + 5]);
        if (id != 0x4) continue;  // INITIAL_WINDOW_SIZE
        const std::int64_t next = static_cast<std::int64_t>(v & 0x7FFFFFFF);
        const std::int64_t delta = next - peerInitialWindow_;
        peerInitialWindow_ = next;
        // RFC 7540 s6.9.2: a new INITIAL_WINDOW_SIZE retroactively adjusts every
        // existing stream by the delta, and the result may go NEGATIVE (a
        // smaller window than we have already spent). Clamping at 0 here would
        // hand out credit the peer never granted, exactly like the bug this
        // whole file just had, so the value is left alone and the negative
        // window simply blocks writes until WINDOW_UPDATE catches up.
        for (auto& kv : streamSendWindow_) kv.second += delta;
        h2_trace("[h2] peer INITIAL_WINDOW_SIZE=%lld (delta %lld)", (long long)next,
                 (long long)delta);
    }
}

// Decodes the fully assembled header block and hands it to the owner.
void H2ServerImpl::deliver_request(std::uint32_t streamId, std::uint8_t flags) {
    Request req;
    req.streamId = streamId;
    std::map<std::string, std::string> hdrs;
    hpack_decode(contBlock_.data(), contBlock_.size(), reqTable_, hdrs);
    contBlock_.clear();
    auto it = hdrs.find(":method");
    req.method = it != hdrs.end() ? it->second : "";
    it = hdrs.find(":path");
    req.path = it != hdrs.end() ? it->second : "";
    for (auto& kv : hdrs) req.headers[kv.first] = kv.second;
    if (!streamSendWindow_.count(streamId)) streamSendWindow_[streamId] = peerInitialWindow_;
    if (cb_.on_request) cb_.on_request(req);
    if (flags & kFlagEndStream && cb_.on_end) cb_.on_end(streamId);
}

bool H2ServerImpl::await_send_window(std::uint32_t streamId, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        auto it = streamSendWindow_.find(streamId);
        const std::int64_t sw = (it == streamSendWindow_.end()) ? peerInitialWindow_ : it->second;
        if (connSendWindow_ > 0 && sw > 0) return true;
        if (closed_ || streamSendWindow_.find(streamId) == streamSendWindow_.end())
            return false;
        h2_trace("[h2] waiting: conn=%lld stream%u=%lld", (long long)connSendWindow_, streamId,
                 (long long)sw);
        if (std::chrono::steady_clock::now() >= deadline) return false;
        // Nothing can be sent until the peer grants credit; keep servicing the
        // connection so WINDOW_UPDATE (and RST_STREAM) actually reach us.
        std::uint8_t type = 0, flags = 0;
        std::uint32_t sid = 0;
        std::vector<std::uint8_t> payload;
        const int got = read_frame(50, type, flags, sid, payload);
        if (got < 0) return false;
        if (got == 0) continue;
        dispatch(type, flags, sid, payload.data(), payload.size());
    }
}

// Returns false only when the connection is gone. A timeout is a normal
// "nothing to read" and must NOT be reported as failure -- but it must also
// not be silently turned into success when the peer actually closed, which is
// what kept a dead tunnel looking healthy and spinning at ~50% CPU.
bool H2ServerImpl::poll(int timeout_ms) {
    std::uint8_t type = 0, flags = 0;
    std::uint32_t sid = 0;
    std::vector<std::uint8_t> payload;
    const int got = read_frame(timeout_ms, type, flags, sid, payload);
    if (got < 0) return false;
    if (got == 0) return true;
    dispatch(type, flags, sid, payload.data(), payload.size());
    return !fatal_;
}

bool H2ServerImpl::write_headers(std::uint32_t streamId, const std::string& status,
                                 const std::vector<std::pair<std::string, std::string>>& extra,
                                 bool endStream) {
    std::vector<std::uint8_t> block;
    // Static table index 8 is (":status", "200"); use the indexed form only for
    // that exact value, otherwise emit a literal. Any other status must be a
    // literal or the peer decodes the wrong code.
    if (status == "200") {
        hpack_int(block, 8, 7, 0x80);
    } else {
        hpack_literal(block, ":status", status);
    }
    // The edge frames the response body from these; a long-lived WebSocket has
    // no length, so send none rather than a stale value from the origin.
    for (auto& kv : extra) hpack_literal(block, kv.first, kv.second);
    std::uint8_t fl = kFlagEndHeaders | (endStream ? kFlagEndStream : 0);
    const bool ok = send_frame(kFrameHeaders, fl, streamId, block.data(), block.size());
    if (!ok) fatal_ = true;
    return ok;
}

bool H2ServerImpl::write_data(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                              bool endStream) {
    constexpr std::size_t kMaxFrame = 16384;
    if (len == 0) {
        return send_frame(kFrameData, endStream ? kFlagEndStream : 0, streamId, nullptr, 0);
    }
    if (resetStreams_.count(streamId)) return false;
    std::size_t off = 0;
    while (off < len) {
        if (!await_send_window(streamId, 30000)) {
            h2_trace("[h2] send window unavailable on stream=%u (%zu/%zu sent)", streamId, off, len);
            return false;
        }
        auto it = streamSendWindow_.find(streamId);
        if (it == streamSendWindow_.end()) {
            it = streamSendWindow_.emplace(streamId, peerInitialWindow_).first;
        }
        std::int64_t& sw = it->second;
        // No "if (sw == 0) sw = peerInitialWindow_" here: 0 is a normal state
        // (credit not granted yet). Reinstating the initial window invented
        // credit the edge never granted; the windows then overran the peer's
        // real buffer, which is what killed long single-connection transfers.
        // await_send_window guarantees credit only for *some* write; a
        // SETTINGS shrink can still leave this stream negative, in which case
        // there is nothing to send yet.
        if (sw <= 0 || connSendWindow_ <= 0) continue;
        std::size_t n = len - off;
        if (n > kMaxFrame) n = kMaxFrame;
        if (static_cast<std::int64_t>(n) > sw) n = static_cast<std::size_t>(sw);
        if (static_cast<std::int64_t>(n) > connSendWindow_)
            n = static_cast<std::size_t>(connSendWindow_);
        const bool last = (off + n >= len);
        const std::uint8_t fl = (last && endStream) ? kFlagEndStream : 0;
        if (!send_frame(kFrameData, fl, streamId, data + off, n)) return false;
        off += n;
        sw -= static_cast<std::int64_t>(n);
        connSendWindow_ -= static_cast<std::int64_t>(n);
    }
    return true;
}

std::size_t H2ServerImpl::write_data_some(std::uint32_t streamId, const std::uint8_t* data,
                                           std::size_t len, bool endStream) {
    constexpr std::size_t kMaxFrame = 16384;
    // The edge reset this stream (RST_STREAM). RFC 7540 s5.1: after sending
    // RST_STREAM the sender must not transmit further frames on it, and the
    // receiver must ignore any it receives. Without this guard the relay kept
    // pushing DATA for a dead stream -- 239 frames in one observed run -- which
    // the edge answers by tearing down the whole connection, so a long download
    // died with no local error at all.
    if (resetStreams_.count(streamId)) return static_cast<std::size_t>(-1);
    if (len == 0) {
        // With no payload only the END_STREAM marker can be sent, which needs
        // no window credit.
        return send_frame(kFrameData, endStream ? kFlagEndStream : 0, streamId, nullptr, 0)
                   ? 0
                   : static_cast<std::size_t>(-1);
    }
    auto it = streamSendWindow_.find(streamId);
    if (it == streamSendWindow_.end()) {
        it = streamSendWindow_.emplace(streamId, peerInitialWindow_).first;
    }
    std::int64_t& sw = it->second;
    if (sw <= 0 || connSendWindow_ <= 0) {
        // This runs on every relay iteration while a window is closed, so it
        // must not log each time: a single long download produced >200k lines
        // and filled the journal. Report the transition only, and rate-limit
        // repeats to once a second per stream.
        trace_credit_wait(streamId, sw, len);
        return 0;  // caller retries later
    }

    std::size_t n = len;
    if (n > kMaxFrame) n = kMaxFrame;
    if (static_cast<std::int64_t>(n) > sw) n = static_cast<std::size_t>(sw);
    if (static_cast<std::int64_t>(n) > connSendWindow_)
        n = static_cast<std::size_t>(connSendWindow_);

    const bool last = (n >= len);
    const std::uint8_t fl = (last && endStream) ? kFlagEndStream : 0;
    if (!send_frame(kFrameData, fl, streamId, data, n)) return static_cast<std::size_t>(-1);
    sw -= static_cast<std::int64_t>(n);
    connSendWindow_ -= static_cast<std::int64_t>(n);
    return n;
}

void H2ServerImpl::trace_credit_wait(std::uint32_t streamId, std::int64_t sw,
                                       std::size_t pending) {
    if (!h2_trace_enabled()) return;
    const auto now = std::chrono::steady_clock::now();
    auto& last = creditWaitLast_;
    auto it = last.find(streamId);
    if (it != last.end() && now - it->second < std::chrono::seconds(1)) return;
    last[streamId] = now;
    h2_trace("[h2] waiting for credit stream=%u conn=%lld sw=%lld pending=%zu", streamId,
             (long long)connSendWindow_, (long long)sw, pending);
}

bool H2ServerImpl::send_credit_available(std::uint32_t streamId) {
    if (connSendWindow_ <= 0) return false;
    auto it = streamSendWindow_.find(streamId);
    // An unknown stream has not been opened by request yet; treat it as
    // available so the first write establishes the window.
    if (it == streamSendWindow_.end()) return true;
    return it->second > 0;
}

bool H2ServerImpl::write_rst_stream(std::uint32_t streamId, std::uint32_t errorCode) {
    streamSendWindow_.erase(streamId);
    std::vector<std::uint8_t> p;
    put_u32(p, errorCode);
    return send_frame(kFrameRstStream, 0, streamId, p.data(), p.size());
}

void H2ServerImpl::close() {
    // Idempotent: the supervisor tears a connection down explicitly and the
    // destructor runs right after, so a second SSL_shutdown/free/close here
    // would touch freed memory and might close an unrelated fd.
    if (closed_ && !ssl_ && fd_ < 0) return;
    closed_ = true;
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

void decode_hpack(const std::uint8_t* block, std::size_t len,
                  std::map<std::string, std::string>& out) {
    static HpackTable tab;  // diagnostics only; no long-lived dynamic state
    hpack_decode(block, len, tab, out);
}

H2Server* H2Server::create(const Callbacks& cb) { return new H2ServerImpl(cb); }

} // namespace bpb::tunnel