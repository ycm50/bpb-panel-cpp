#include "inbound/proto/h2s.h"

#include "net/tls.h"
#include "util/log.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

#ifdef _WIN32
#include <mstcpip.h>   // tcp_keepalive / SIO_KEEPALIVE_VALS
#else
#include <netinet/tcp.h>   // TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT
#endif

namespace bpb::proxy::h2s {

namespace {

constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kPrefaceLen = sizeof(kPreface) - 1;

// Frame types (RFC 7540 s6).
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

// Settings identifiers we care about (RFC 7540 s6.5.2).
enum : std::uint16_t {
    kSetHeaderTableSize = 0x01,
    kSetEnablePush = 0x02,
    kSetMaxConcurrentStreams = 0x03,
    kSetInitialWindowSize = 0x04,
    kSetMaxFrameSize = 0x05,
};

// SETTINGS_HEADER_TABLE_SIZE we advertise. The protocol default; the decoder
// clamps any table-size update to it, because a peer may not enlarge the table
// beyond what we offered.
constexpr std::size_t kHeaderTableSize = 4096;

// Largest frame payload we accept from the peer. We advertise the protocol
// default of 16384, so anything near this is already a peer bug; the bound
// exists so a hostile length field cannot make us allocate 16 MiB (the frame
// length field is 24 bits).
constexpr std::uint32_t kMaxFramePayload = 256 * 1024;

// RFC 7540 s6.9.1: a flow-control window must never exceed 2^31-1.
constexpr std::int64_t kMaxWindow = 0x7FFFFFFF;

// Control/data writes are batched into ~32 KiB TLS records: one record per
// frame cost two SSL_write calls per 16 KiB, which is where most of the CPU per
// byte used to go.
constexpr std::size_t kTxBatch = 32 * 1024;

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void put_u32(std::string& out, std::uint32_t v) {
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>(v & 0xFF));
}

std::uint32_t get_u32(const char* p) {
    const auto* u = reinterpret_cast<const unsigned char*>(p);
    return (static_cast<std::uint32_t>(u[0]) << 24) | (static_cast<std::uint32_t>(u[1]) << 16) |
           (static_cast<std::uint32_t>(u[2]) << 8) | static_cast<std::uint32_t>(u[3]);
}

// Frame-level tracing is opt-in (--log trace / BPB_LOG=trace) and never on by
// default: a per-frame line on a bulk transfer would flood the journal.
void trace(const char* fmt, ...) {
    if (!bpb::log::enabled(bpb::log::kTrace)) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

// Dead peers are invisible to a relay: the peer can vanish without a FIN and a
// session then waits for bytes that will never come. TCP keepalive makes the
// kernel notice instead of leaving one thread per dead connection behind.
void enable_keepalive(net::socket_t fd) {
    if (fd == net::kInvalid) return;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef _WIN32
    tcp_keepalive ka{1, 60000, 15000};
    DWORD bytes = 0;
    WSAIoctl(fd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes, nullptr, nullptr);
#else
    int idle = 60;
    int intvl = 15;
    int cnt = 4;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

// ---- HPACK (RFC 7541) ------------------------------------------------------
// The decoder is the part that matters: every real client (grpc-go, nghttp2,
// Chrome) sends Huffman-coded literals and uses the incremental-indexing
// representation, so a static-table-only decoder works on hand-written frames
// and fails the moment a real client connects.

struct HpackTable {
    std::vector<Header> dynamic;
    std::size_t size = 0;   // bytes in use (RFC 7541 s4.1)
    std::size_t max = kHeaderTableSize;
};

const char* const kStatic[61][2] = {
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


// ---- HPACK Huffman codec (RFC 7541 Appendix B) -----------------------------
// Table data from nghttp2 (MIT licensed), kept verbatim in this file so the
// transport has no dependency outside src/inbound.
// HPACK Huffman code table (RFC 7541 Appendix B), generated from nghttp2 (MIT).
// kHuffBits[i] = code length in bits, kHuffCodes[i] = code left-aligned in 32 bits.
static const unsigned short kHuffBits[257] = {
13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30
};
static const unsigned int kHuffCodes[257] = {
0xFFC00000u, 0xFFFFB000u, 0xFFFFFE20u, 0xFFFFFE30u, 0xFFFFFE40u, 0xFFFFFE50u, 0xFFFFFE60u, 0xFFFFFE70u, 0xFFFFFE80u, 0xFFFFEA00u, 0xFFFFFFF0u, 0xFFFFFE90u, 0xFFFFFEA0u, 0xFFFFFFF4u, 0xFFFFFEB0u, 0xFFFFFEC0u, 0xFFFFFED0u, 0xFFFFFEE0u, 0xFFFFFEF0u, 0xFFFFFF00u, 0xFFFFFF10u, 0xFFFFFF20u, 0xFFFFFFF8u, 0xFFFFFF30u, 0xFFFFFF40u, 0xFFFFFF50u, 0xFFFFFF60u, 0xFFFFFF70u, 0xFFFFFF80u, 0xFFFFFF90u, 0xFFFFFFA0u, 0xFFFFFFB0u, 0x50000000u, 0xFE000000u, 0xFE400000u, 0xFFA00000u, 0xFFC80000u, 0x54000000u, 0xF8000000u, 0xFF400000u, 0xFE800000u, 0xFEC00000u, 0xF9000000u, 0xFF600000u, 0xFA000000u, 0x58000000u, 0x5C000000u, 0x60000000u, 0x0u, 0x8000000u, 0x10000000u, 0x64000000u, 0x68000000u, 0x6C000000u, 0x70000000u, 0x74000000u, 0x78000000u, 0x7C000000u, 0xB8000000u, 0xFB000000u, 0xFFF80000u, 0x80000000u, 0xFFB00000u, 0xFF000000u, 0xFFD00000u, 0x84000000u, 0xBA000000u, 0xBC000000u, 0xBE000000u, 0xC0000000u, 0xC2000000u, 0xC4000000u, 0xC6000000u, 0xC8000000u, 0xCA000000u, 0xCC000000u, 0xCE000000u, 0xD0000000u, 0xD2000000u, 0xD4000000u, 0xD6000000u, 0xD8000000u, 0xDA000000u, 0xDC000000u, 0xDE000000u, 0xE0000000u, 0xE2000000u, 0xE4000000u, 0xFC000000u, 0xE6000000u, 0xFD000000u, 0xFFD80000u, 0xFFFE0000u, 0xFFE00000u, 0xFFF00000u, 0x88000000u, 0xFFFA0000u, 0x18000000u, 0x8C000000u, 0x20000000u, 0x90000000u, 0x28000000u, 0x94000000u, 0x98000000u, 0x9C000000u, 0x30000000u, 0xE8000000u, 0xEA000000u, 0xA0000000u, 0xA4000000u, 0xA8000000u, 0x38000000u, 0xAC000000u, 0xEC000000u, 0xB0000000u, 0x40000000u, 0x48000000u, 0xB4000000u, 0xEE000000u, 0xF0000000u, 0xF2000000u, 0xF4000000u, 0xF6000000u, 0xFFFC0000u, 0xFF800000u, 0xFFF40000u, 0xFFE80000u, 0xFFFFFFC0u, 0xFFFE6000u, 0xFFFF4800u, 0xFFFE7000u, 0xFFFE8000u, 0xFFFF4C00u, 0xFFFF5000u, 0xFFFF5400u, 0xFFFFB200u, 0xFFFF5800u, 0xFFFFB400u, 0xFFFFB600u, 0xFFFFB800u, 0xFFFFBA00u, 0xFFFFBC00u, 0xFFFFEB00u, 0xFFFFBE00u, 0xFFFFEC00u, 0xFFFFED00u, 0xFFFF5C00u, 0xFFFFC000u, 0xFFFFEE00u, 0xFFFFC200u, 0xFFFFC400u, 0xFFFFC600u, 0xFFFFC800u, 0xFFFEE000u, 0xFFFF6000u, 0xFFFFCA00u, 0xFFFF6400u, 0xFFFFCC00u, 0xFFFFCE00u, 0xFFFFEF00u, 0xFFFF6800u, 0xFFFEE800u, 0xFFFE9000u, 0xFFFF6C00u, 0xFFFF7000u, 0xFFFFD000u, 0xFFFFD200u, 0xFFFEF000u, 0xFFFFD400u, 0xFFFF7400u, 0xFFFF7800u, 0xFFFFF000u, 0xFFFEF800u, 0xFFFF7C00u, 0xFFFFD600u, 0xFFFFD800u, 0xFFFF0000u, 0xFFFF0800u, 0xFFFF8000u, 0xFFFF1000u, 0xFFFFDA00u, 0xFFFF8400u, 0xFFFFDC00u, 0xFFFFDE00u, 0xFFFEA000u, 0xFFFF8800u, 0xFFFF8C00u, 0xFFFF9000u, 0xFFFFE000u, 0xFFFF9400u, 0xFFFF9800u, 0xFFFFE200u, 0xFFFFF800u, 0xFFFFF840u, 0xFFFEB000u, 0xFFFE2000u, 0xFFFF9C00u, 0xFFFFE400u, 0xFFFFA000u, 0xFFFFF600u, 0xFFFFF880u, 0xFFFFF8C0u, 0xFFFFF900u, 0xFFFFFBC0u, 0xFFFFFBE0u, 0xFFFFF940u, 0xFFFFF100u, 0xFFFFF680u, 0xFFFE4000u, 0xFFFF1800u, 0xFFFFF980u, 0xFFFFFC00u, 0xFFFFFC20u, 0xFFFFF9C0u, 0xFFFFFC40u, 0xFFFFF200u, 0xFFFF2000u, 0xFFFF2800u, 0xFFFFFA00u, 0xFFFFFA40u, 0xFFFFFFD0u, 0xFFFFFC60u, 0xFFFFFC80u, 0xFFFFFCA0u, 0xFFFEC000u, 0xFFFFF300u, 0xFFFED000u, 0xFFFF3000u, 0xFFFFA400u, 0xFFFF3800u, 0xFFFF4000u, 0xFFFFE600u, 0xFFFFA800u, 0xFFFFAC00u, 0xFFFFF700u, 0xFFFFF780u, 0xFFFFF400u, 0xFFFFF500u, 0xFFFFFA80u, 0xFFFFE800u, 0xFFFFFAC0u, 0xFFFFFCC0u, 0xFFFFFB00u, 0xFFFFFB40u, 0xFFFFFCE0u, 0xFFFFFD00u, 0xFFFFFD20u, 0xFFFFFD40u, 0xFFFFFD60u, 0xFFFFFFE0u, 0xFFFFFD80u, 0xFFFFFDA0u, 0xFFFFFDC0u, 0xFFFFFDE0u, 0xFFFFFE00u, 0xFFFFFB80u, 0xFFFFFFFCu
};

bool huffman_decode(const std::uint8_t* data, std::size_t len, std::string& out) {
    out.clear();
    out.reserve(len);
    std::uint64_t acc = 0;
    int bits = 0;
    std::size_t i = 0;
    for (;;) {
        bool matched = false;
        for (int s = 0; s < 256; ++s) {
            const int bl = kHuffBits[s];
            if (bl > bits) continue;
            const std::uint32_t code = kHuffCodes[s] >> (32 - bl);
            const std::uint64_t mask = (1ull << bl) - 1;
            if (((acc >> (bits - bl)) & mask) == code) {
                out.push_back(static_cast<char>(s));
                bits -= bl;
                matched = true;
                break;
            }
        }
        if (matched) continue;
        // No code matches what is buffered. That means either "not enough bits
        // yet" -- a symbol may end in the middle of a byte, so the window has to
        // grow -- or the EOS padding at the very end of the input. Conflating
        // the two truncates every Huffman header value at the first such
        // boundary: "/vlg/Tun" arrives as "/vl", "application/grpc" as "ap".
        if (i >= len) {
            // Leftover bits are padding: fewer than 8 of them (RFC 7541 s5.2).
            return bits < 8;
        }
        acc = (acc << 8) | static_cast<std::uint64_t>(data[i++]);
        bits += 8;
    }
}

bool hpack_int(const std::uint8_t* p, std::size_t len, std::size_t& pos, int prefix,
               std::uint32_t& out) {
    if (pos >= len) return false;
    const std::uint32_t mask = (1u << prefix) - 1;
    std::uint32_t v = p[pos] & mask;
    ++pos;
    if (v < mask) {
        out = v;
        return true;
    }
    std::uint32_t shift = 0;
    while (pos < len) {
        const std::uint8_t b = p[pos++];
        v += static_cast<std::uint32_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            out = v;
            return true;
        }
        shift += 7;
        if (shift > 28) return false;   // a length this large is not a length
    }
    return false;
}

bool hpack_string(const std::uint8_t* p, std::size_t len, std::size_t& pos, std::string& out) {
    if (pos >= len) return false;
    const bool huffman = (p[pos] & 0x80) != 0;
    std::uint32_t n = 0;
    if (!hpack_int(p, len, pos, 7, n)) return false;
    if (n > len - pos) return false;
    if (huffman) {
        if (!huffman_decode(p + pos, n, out)) return false;
    } else {
        out.assign(reinterpret_cast<const char*>(p + pos), n);
    }
    pos += n;
    return true;
}

void table_evict(HpackTable& t) {
    while (t.size > t.max && !t.dynamic.empty()) {
        t.size -= t.dynamic.back().first.size() + t.dynamic.back().second.size() + 32;
        t.dynamic.pop_back();
    }
}

void table_insert(HpackTable& t, const std::string& name, const std::string& value) {
    const std::size_t entry = name.size() + value.size() + 32;
    if (entry > t.max) {
        // RFC 7541 s4.4: an entry larger than the whole table empties it.
        t.dynamic.clear();
        t.size = 0;
        return;
    }
    t.dynamic.insert(t.dynamic.begin(), Header{name, value});
    t.size += entry;
    table_evict(t);
}

// Indexed header field, 1-based, static table first (RFC 7541 s2.3.3).
const Header* table_lookup(const HpackTable& t, std::uint32_t idx) {
    if (idx >= 1 && idx <= 61) {
        static Header cache[61];
        static bool init = false;
        if (!init) {
            for (int i = 0; i < 61; ++i) cache[i] = Header{kStatic[i][0], kStatic[i][1]};
            init = true;
        }
        return &cache[idx - 1];
    }
    const std::uint32_t d = idx - 62;
    if (d < t.dynamic.size()) return &t.dynamic[d];
    return nullptr;
}

bool hpack_decode(const std::uint8_t* p, std::size_t len, HpackTable& tab, Headers& out) {
    std::size_t pos = 0;
    while (pos < len) {
        const std::uint8_t b = p[pos];
        if (b & 0x80) {   // 1xxxxxxx: indexed header field
            std::uint32_t idx = 0;
            if (!hpack_int(p, len, pos, 7, idx)) return false;
            const Header* e = table_lookup(tab, idx);
            if (!e) return false;
            out.push_back(*e);
        } else if ((b & 0xC0) == 0x40) {   // 01xxxxxx: literal, incremental indexing
            std::uint32_t idx = 0;
            if (!hpack_int(p, len, pos, 6, idx)) return false;
            std::string name;
            std::string value;
            if (idx == 0) {
                if (!hpack_string(p, len, pos, name)) return false;
            } else {
                const Header* e = table_lookup(tab, idx);
                if (!e) return false;
                name = e->first;
            }
            if (!hpack_string(p, len, pos, value)) return false;
            out.push_back(Header{name, value});
            table_insert(tab, name, value);
        } else if ((b & 0xE0) == 0x20) {   // 001xxxxx: dynamic table size update
            std::uint32_t v = 0;
            if (!hpack_int(p, len, pos, 5, v)) return false;
            // The peer may shrink the table but never grow it past our
            // SETTINGS_HEADER_TABLE_SIZE; clamping keeps both sides agreeing on
            // what is in the table.
            tab.max = std::min<std::size_t>(v, kHeaderTableSize);
            table_evict(tab);
        } else {   // 0000xxxx / 0001xxxx: literal without indexing
            std::uint32_t idx = 0;
            if (!hpack_int(p, len, pos, 4, idx)) return false;
            std::string name;
            std::string value;
            if (idx == 0) {
                if (!hpack_string(p, len, pos, name)) return false;
            } else {
                const Header* e = table_lookup(tab, idx);
                if (!e) return false;
                name = e->first;
            }
            if (!hpack_string(p, len, pos, value)) return false;
            out.push_back(Header{name, value});
        }
    }
    return true;
}

// ---- HPACK encoder (the minimum the transport needs) -----------------------

void encode_int(std::string& out, std::uint32_t v, int prefix, std::uint8_t first) {
    const std::uint32_t limit = (1u << prefix) - 1;
    if (v < limit) {
        out.push_back(static_cast<char>(first | v));
        return;
    }
    out.push_back(static_cast<char>(first | limit));
    v -= limit;
    while (v >= 128) {
        out.push_back(static_cast<char>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<char>(v));
}

void encode_string(std::string& out, const std::string& s) {
    encode_int(out, static_cast<std::uint32_t>(s.size()), 7, 0x00);
    out += s;
}

// "Literal header field without indexing": the peer's decoder never has to
// track state for us, so our encoder cannot desynchronise from its table over a
// connection that lives for days.
void encode_field(std::string& out, const std::string& name, const std::string& value) {
    if (name == ":status" && value == "200") {
        out.push_back(static_cast<char>(0x88));   // static index 8
        return;
    }
    int idx = 0;
    for (int i = 0; i < 61; ++i) {
        if (name == kStatic[i][0]) {
            idx = i + 1;
            break;
        }
    }
    if (idx > 0) {
        encode_int(out, static_cast<std::uint32_t>(idx), 4, 0x00);
    } else {
        out.push_back(0x00);
        encode_string(out, name);
    }
    encode_string(out, value);
}


// ---------------------------------------------------------------------------

struct FrameHead {
    std::uint32_t len = 0;
    std::uint32_t sid = 0;
    std::uint8_t type = 0;
    std::uint8_t flags = 0;
};

class ServerImpl final : public Server {
public:
    ServerImpl(net::socket_t fd, SSL* ssl, std::string buffered, Handlers handlers,
               const Settings& cfg)
        : fd_(fd),
          ssl_(ssl),
          handlers_(std::move(handlers)),
          cfg_(cfg),
          in_(std::move(buffered)) {
        last_rx_ = now_ms();
    }

    ~ServerImpl() override { release(); }

    void run() override;
    bool write_data(std::uint32_t stream, const char* data, std::size_t len) override;
    bool write_headers(std::uint32_t stream, const Headers& headers, bool end_stream) override;
    void consume(std::uint32_t stream, std::size_t bytes) override;
    void rst_stream(std::uint32_t stream, std::uint32_t code) override;
    void close_stream(std::uint32_t stream) override;
    bool alive() const override { return alive_.load(); }

private:
    struct StreamState {
        // Credit the peer has granted us for DATA on this stream.
        std::int64_t send_window = 65535;
        // Bytes handed to the session but not consumed yet.
        std::int64_t outstanding = 0;
        // Consumed bytes whose WINDOW_UPDATE has not been sent yet.
        std::int64_t credit = 0;
        bool reset = false;
        bool local_end = false;
        bool remote_end = false;
    };

    // --- input side (connection thread only)
    int fill(std::size_t need, int timeout_ms);
    int read_frame(FrameHead& h);
    void dispatch(const FrameHead& h, const char* body);
    void on_settings(const FrameHead& h, const char* body);
    void on_window_update(const FrameHead& h, const char* body);
    void on_headers_frame(const FrameHead& h, const char* body);
    void on_continuation(const FrameHead& h, const char* body);
    void on_data_frame(const FrameHead& h, const char* body);
    void on_rst_stream(const FrameHead& h, const char* body);
    void finish_header_block(std::uint32_t sid, bool end_stream);
    // Blocks (in slices) while more than max_buffered bytes await the sessions.
    bool wait_for_room();
    void release();

    // --- output side (any thread; wmu_ serialises, frame builders assume it)
    void append_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid, const char* payload,
                      std::size_t len);
    bool flush_locked();
    bool flush();
    bool send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid, const char* payload,
                    std::size_t len, bool batch);
    bool write_header_block(std::uint32_t sid, const std::string& block, bool end_stream);
    void go_away(std::uint32_t code);

    net::socket_t fd_ = net::kInvalid;
    SSL* ssl_ = nullptr;

    Handlers handlers_;
    Settings cfg_;
    HpackTable hpack_;

    // Input buffer: the preface, then frame bytes. Kept as a string so the
    // HTTP layer can hand over what it already read.
    std::string in_;

    // Output buffer for the current TLS record.
    std::string tx_;

    std::mutex wmu_;   // guards tx_, ssl_ lifetime and alive_ transitions
    std::mutex mu_;    // guards the members below
    std::condition_variable cv_;
    std::atomic<bool> alive_{true};
    bool released_ = false;

    std::unordered_map<std::uint32_t, StreamState> streams_;
    std::int64_t outstanding_total_ = 0;

    // Send windows: ours on the connection, and what the peer's SETTINGS say a
    // fresh stream starts with.
    std::int64_t conn_send_ = 65535;
    std::int64_t peer_initial_window_ = 65535;
    std::atomic<std::uint32_t> peer_max_frame_{16384};

    // Receive-credit batching.
    std::int64_t conn_credit_ = 0;

    // The header block being assembled across HEADERS + CONTINUATION.
    std::uint32_t cont_sid_ = 0;
    std::string cont_block_;

    std::uint32_t last_stream_id_ = 0;
    std::int64_t last_rx_ = 0;

    // Diagnostics (one summary line per connection at debug level).
    unsigned long long frames_ = 0;
    unsigned long long streams_opened_ = 0;
    unsigned long long bytes_rx_ = 0;
    unsigned long long bytes_tx_ = 0;
    const char* end_reason_ = "peer closed";
};

int ServerImpl::fill(std::size_t need, int timeout_ms) {
    const std::int64_t deadline = now_ms() + timeout_ms;
    while (in_.size() < need) {
        char buf[16384];
        net::IoResult result = net::IoResult::Error;
        const int n = net::tls_read(ssl_, fd_, buf, static_cast<int>(sizeof(buf)), result);
        if (n > 0) {
            in_.append(buf, static_cast<std::size_t>(n));
            continue;
        }
        if (result == net::IoResult::WouldBlock) {
            // TLS can hold decrypted bytes that never raise a socket event.
            if (net::tls_pending(ssl_) > 0) continue;
            const std::int64_t left = deadline - now_ms();
            if (left <= 0) return 0;
            net::PollFd pfd{fd_, net::kRead, 0};
            const int pr = net::poll_fds(&pfd, 1, static_cast<int>(left));
            if (pr > 0) continue;
            if (pr == 0) return 0;
            return -1;
        }
        return -1;
    }
    return 1;
}

int ServerImpl::read_frame(FrameHead& h) {
    int rc = fill(9, 200);
    if (rc <= 0) return rc;
    const auto* p = reinterpret_cast<const unsigned char*>(in_.data());
    h.len = (static_cast<std::uint32_t>(p[0]) << 16) | (static_cast<std::uint32_t>(p[1]) << 8) |
            static_cast<std::uint32_t>(p[2]);
    h.type = p[3];
    h.flags = p[4];
    h.sid = ((static_cast<std::uint32_t>(p[5]) << 24) | (static_cast<std::uint32_t>(p[6]) << 16) |
             (static_cast<std::uint32_t>(p[7]) << 8) | static_cast<std::uint32_t>(p[8])) &
            0x7FFFFFFFu;
    if (h.len > kMaxFramePayload) {
        end_reason_ = "frame too large";
        go_away(kFrameSizeError);
        return -1;
    }
    rc = fill(9 + h.len, 200);
    if (rc <= 0) return rc;
    frames_++;
    bytes_rx_ += 9 + h.len;
    return 1;
}

void ServerImpl::dispatch(const FrameHead& h, const char* body) {
    trace("[h2 rx] type=%u flags=0x%02x stream=%u len=%u", h.type, h.flags, h.sid, h.len);
    switch (h.type) {
        case kFrameSettings:
            on_settings(h, body);
            break;
        case kFrameWindowUpdate:
            on_window_update(h, body);
            break;
        case kFramePing:
            // A PING must be echoed byte for byte, even when it arrives while a
            // session is busy: it is the only liveness signal an idle gRPC
            // connection produces.
            if (!(h.flags & kFlagAck) && h.len == 8)
                send_frame(kFramePing, kFlagAck, 0, body, 8, false);
            break;
        case kFrameHeaders:
            on_headers_frame(h, body);
            break;
        case kFrameContinuation:
            on_continuation(h, body);
            break;
        case kFrameData:
            on_data_frame(h, body);
            break;
        case kFrameRstStream:
            on_rst_stream(h, body);
            break;
        case kFrameGoAway:
            // The peer will not accept another stream; whatever is running may
            // finish. Nothing to do but stop reading.
            end_reason_ = "peer goaway";
            alive_.store(false);
            cv_.notify_all();
            break;
        case kFramePriority:      // deprecated in RFC 9113, never meaningful here
        case kFramePushPromise:   // a server must not receive one
            break;
        default:
            break;   // unknown frame types must be ignored (RFC 7540 s4.1)
    }
}

void ServerImpl::on_settings(const FrameHead& h, const char* body) {
    if (h.flags & kFlagAck) return;   // acknowledgement of ours: nothing to do
    if (h.len % 6 != 0) {
        end_reason_ = "bad SETTINGS";
        go_away(kFrameSizeError);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (std::uint32_t off = 0; off + 6 <= h.len; off += 6) {
            const auto* u = reinterpret_cast<const unsigned char*>(body + off);
            const std::uint16_t id = static_cast<std::uint16_t>((std::uint16_t(u[0]) << 8) | u[1]);
            const std::uint32_t value = get_u32(body + off + 2);
            switch (id) {
                case kSetInitialWindowSize: {
                    // Applies to every stream that is already open as a delta
                    // (RFC 7540 s6.9.2). Getting this wrong is what makes a
                    // download stall at 64 KiB and then hang for ever.
                    const std::int64_t delta =
                        static_cast<std::int64_t>(value) - peer_initial_window_;
                    peer_initial_window_ = value;
                    for (auto& kv : streams_) kv.second.send_window += delta;
                    break;
                }
                case kSetMaxFrameSize:
                    // The largest DATA frame we may send; clamped because a
                    // peer is not allowed to offer less than 16384.
                    peer_max_frame_.store(std::clamp<std::uint32_t>(value, 16384, 1u << 20));
                    break;
                case kSetHeaderTableSize:
                    // Bounds the table *we* build while encoding. Our encoder
                    // never uses the dynamic table, so nothing to do.
                default:
                    break;
            }
        }
    }
    cv_.notify_all();
    send_frame(kFrameSettings, kFlagAck, 0, nullptr, 0, false);
}

void ServerImpl::on_window_update(const FrameHead& h, const char* body) {
    if (h.len < 4) return;
    const std::uint32_t inc = get_u32(body) & 0x7FFFFFFFu;
    if (inc == 0) return;
    bool overflow = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (h.sid == 0) {
            conn_send_ += inc;
            overflow = conn_send_ > kMaxWindow;
        } else {
            auto it = streams_.find(h.sid);
            // A WINDOW_UPDATE for a stream we already forgot is legal: the peer
            // may have written it before it saw our RST_STREAM.
            if (it != streams_.end()) {
                it->second.send_window += inc;
                overflow = it->second.send_window > kMaxWindow;
            }
        }
    }
    if (overflow) {
        end_reason_ = "window overflow";
        go_away(kFlowControlError);
        return;
    }
    cv_.notify_all();
}

void ServerImpl::on_headers_frame(const FrameHead& h, const char* body) {
    if (h.sid == 0) {
        end_reason_ = "HEADERS on stream 0";
        go_away(kProtocolError);
        return;
    }
    std::size_t off = 0;
    std::size_t end = h.len;
    if (h.flags & kFlagPadded) {
        if (h.len < 1) return;
        const std::size_t pad = static_cast<unsigned char>(body[0]);
        if (pad + 1 > h.len) {
            end_reason_ = "bad padding";
            go_away(kProtocolError);
            return;
        }
        off = 1;
        end = h.len - pad;
    }
    if (h.flags & kFlagPriority) off += 5;   // exclusive flag + dependency + weight
    if (off > end) {
        end_reason_ = "bad HEADERS";
        go_away(kProtocolError);
        return;
    }
    // Stream ids only ever grow (RFC 7540 s5.1.1): a header block for an id that
    // is not open yet and not above the high-water mark is a reuse. The check has
    // to look at the open set, because trailers legitimately carry a lower id.
    bool reuse = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        reuse = streams_.find(h.sid) == streams_.end() && h.sid <= last_stream_id_;
    }
    if (reuse) {
        end_reason_ = "stream id reuse";
        go_away(kProtocolError);
        return;
    }
    if (h.sid > last_stream_id_) last_stream_id_ = h.sid;
    cont_sid_ = h.sid;
    cont_block_.assign(body + off, end - off);
    if (h.flags & kFlagEndHeaders) finish_header_block(h.sid, (h.flags & kFlagEndStream) != 0);
}

void ServerImpl::on_continuation(const FrameHead& h, const char* body) {
    if (h.sid != cont_sid_ || cont_sid_ == 0) {
        end_reason_ = "unexpected CONTINUATION";
        go_away(kProtocolError);
        return;
    }
    cont_block_.append(body, h.len);
    if (cont_block_.size() > 256 * 1024) {   // a header block this large is an attack
        end_reason_ = "header block too large";
        go_away(kEnhanceYourCalm);
        return;
    }
    if (h.flags & kFlagEndHeaders) finish_header_block(h.sid, (h.flags & kFlagEndStream) != 0);
}

void ServerImpl::finish_header_block(std::uint32_t sid, bool end_stream) {
    Headers headers;
    const bool ok = hpack_decode(reinterpret_cast<const std::uint8_t*>(cont_block_.data()),
                                cont_block_.size(), hpack_, headers);
    cont_block_.clear();
    cont_sid_ = 0;
    if (!ok) {
        end_reason_ = "HPACK decode failed";
        rst_stream(sid, kProtocolError);
        return;
    }
    bool fresh = false;
    bool refused = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(sid);
        if (it == streams_.end()) {
            if (streams_.size() >= cfg_.max_concurrent_streams) {
                refused = true;
            } else {
                StreamState st;
                st.send_window = peer_initial_window_;
                it = streams_.emplace(sid, st).first;
                fresh = true;
                streams_opened_++;
            }
        }
        if (!refused && end_stream) it->second.remote_end = true;
    }
    if (refused) {
        rst_stream(sid, kRefusedStream);
        return;
    }
    if (!fresh) {
        // A second header block on a live stream is a trailer: the request is
        // over as far as the transport is concerned.
        if (end_stream && handlers_.on_end_stream) handlers_.on_end_stream(sid);
        return;
    }
    if (handlers_.on_headers) handlers_.on_headers(sid, headers);
}

void ServerImpl::on_data_frame(const FrameHead& h, const char* body) {
    if (h.sid == 0) {
        end_reason_ = "DATA on stream 0";
        go_away(kProtocolError);
        return;
    }
    std::size_t off = 0;
    std::size_t end = h.len;
    if (h.flags & kFlagPadded) {
        if (h.len < 1) {
            end_reason_ = "bad padding";
            go_away(kProtocolError);
            return;
        }
        const std::size_t pad = static_cast<unsigned char>(body[0]);
        if (pad + 1 > h.len) {
            end_reason_ = "bad padding";
            go_away(kProtocolError);
            return;
        }
        off = 1;
        end = h.len - pad;
    }
    const std::size_t payload = end - off;

    bool known = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(h.sid);
        if (it != streams_.end()) {
            // The whole frame counts against the window, padding included; the
            // session only ever sees the payload, so the rest is credited here.
            it->second.outstanding += static_cast<std::int64_t>(h.len);
            outstanding_total_ += static_cast<std::int64_t>(h.len);
            known = true;
        }
    }
    if (known && payload && handlers_.on_data) handlers_.on_data(h.sid, body + off, payload);
    const std::size_t framed = h.len - payload;
    if (known && framed) consume(h.sid, framed);
    if (known && (h.flags & kFlagEndStream)) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = streams_.find(h.sid);
            if (it != streams_.end()) it->second.remote_end = true;
        }
        if (handlers_.on_end_stream) handlers_.on_end_stream(h.sid);
    }
}

void ServerImpl::on_rst_stream(const FrameHead& h, const char* body) {
    if (h.len < 4) return;
    bool existed = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(h.sid);
        if (it != streams_.end()) {
            outstanding_total_ -= it->second.outstanding;
            if (outstanding_total_ < 0) outstanding_total_ = 0;
            streams_.erase(it);
            existed = true;
        }
    }
    trace("[h2] RST_STREAM stream=%u code=%u", h.sid, get_u32(body));
    if (existed && handlers_.on_reset_stream) handlers_.on_reset_stream(h.sid);
}

void ServerImpl::go_away(std::uint32_t code) {
    if (!alive_.load()) return;
    std::string payload;
    put_u32(payload, last_stream_id_ & 0x7FFFFFFFu);
    put_u32(payload, code);
    send_frame(kFrameGoAway, 0, 0, payload.data(), payload.size(), false);
    alive_.store(false);
    cv_.notify_all();
}

bool ServerImpl::wait_for_room() {
    std::unique_lock<std::mutex> lk(mu_);
    while (alive_.load() && outstanding_total_ > static_cast<std::int64_t>(cfg_.max_buffered)) {
        cv_.wait_for(lk, std::chrono::milliseconds(50));
        if (now_ms() - last_rx_ > cfg_.idle_ms) {
            // A connection whose session has not drained a byte for a minute is
            // not going to: give the slot back instead of holding 4 MiB for ever.
            lk.unlock();
            end_reason_ = "buffered too long";
            return false;
        }
    }
    return alive_.load();
}

void ServerImpl::run() {
    enable_keepalive(fd_);
    // The HTTP layer only hands over a connection once it has read the complete
    // preface, so this comparison cannot be short.
    if (in_.size() < kPrefaceLen || in_.compare(0, kPrefaceLen, kPreface, kPrefaceLen) != 0) {
        end_reason_ = "no preface";
        release();
        return;
    }
    in_.erase(0, kPrefaceLen);

    // Our SETTINGS: the stream window the peer may fill, and how many streams we
    // are willing to run at once.
    std::string settings;
    settings.push_back(0x00);
    settings.push_back(static_cast<char>(kSetEnablePush));
    put_u32(settings, 0);   // servers never push; tell the peer not to ask
    settings.push_back(0x00);
    settings.push_back(static_cast<char>(kSetMaxConcurrentStreams));
    put_u32(settings, cfg_.max_concurrent_streams);
    settings.push_back(0x00);
    settings.push_back(static_cast<char>(kSetInitialWindowSize));
    put_u32(settings, cfg_.stream_window);
    if (!send_frame(kFrameSettings, 0, 0, settings.data(), settings.size(), false)) {
        release();
        return;
    }
    // The connection-level window starts at the protocol default of 65535 and
    // only grows through WINDOW_UPDATE; open it before the peer starts sending.
    if (cfg_.connection_window > 65535) {
        std::string inc;
        put_u32(inc, cfg_.connection_window - 65535);
        if (!send_frame(kFrameWindowUpdate, 0, 0, inc.data(), inc.size(), false)) {
            release();
            return;
        }
    }

    FrameHead h;
    while (alive_.load()) {
        if (!wait_for_room()) break;
        const int rc = read_frame(h);
        if (rc < 0) break;
        if (rc == 0) {
            if (now_ms() - last_rx_ > cfg_.idle_ms) {
                end_reason_ = "idle";
                break;
            }
            continue;
        }
        last_rx_ = now_ms();
        // A header block may not be interrupted (RFC 7540 s6.10).
        if (cont_sid_ != 0 && h.type != kFrameContinuation) {
            end_reason_ = "interleaved header block";
            go_away(kProtocolError);
            break;
        }
        dispatch(h, in_.data() + 9);
        in_.erase(0, 9 + h.len);
    }
    release();
}

bool ServerImpl::write_data(std::uint32_t sid, const char* data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        std::size_t chunk = 0;
        {
            std::unique_lock<std::mutex> lk(mu_);
            // Re-look the stream up after every wait: a reference into the map
            // would dangle the moment the connection opens another stream and the
            // hash table rehashes underneath it.
            for (;;) {
                auto it = streams_.find(sid);
                if (it == streams_.end()) return false;
                const StreamState& st = it->second;
                if (!alive_.load() || st.reset || st.local_end) return false;
                // A SETTINGS_INITIAL_WINDOW_SIZE reduction may have pushed a
                // window below zero; only a strictly positive window may carry
                // bytes.
                if (conn_send_ > 0 && st.send_window > 0) {
                    const std::int64_t room = std::min(conn_send_, st.send_window);
                    chunk = std::min<std::size_t>(
                        {len - off, static_cast<std::size_t>(room),
                         static_cast<std::size_t>(peer_max_frame_.load())});
                    if (chunk == 0) continue;
                    conn_send_ -= static_cast<std::int64_t>(chunk);
                    it->second.send_window -= static_cast<std::int64_t>(chunk);
                    break;
                }
                // Bounded waits: a closed window is normal (the peer is
                // draining), a connection that died must not trap the caller.
                cv_.wait_for(lk, std::chrono::milliseconds(50));
            }
        }
        if (!send_frame(kFrameData, 0, sid, data + off, chunk, true)) return false;
        off += chunk;
    }
    return flush();
}

bool ServerImpl::write_headers(std::uint32_t sid, const Headers& headers, bool end_stream) {
    std::string block;
    for (const Header& f : headers) encode_field(block, f.first, f.second);
    if (end_stream) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(sid);
        if (it != streams_.end()) it->second.local_end = true;
    }
    return write_header_block(sid, block, end_stream);
}

bool ServerImpl::write_header_block(std::uint32_t sid, const std::string& block, bool end_stream) {
    // Our blocks are a handful of bytes; the split exists so a future caller
    // with a big field set cannot emit a frame the peer must reject.
    constexpr std::size_t kChunkMax = 16384;   // every peer accepts at least this
    std::size_t off = 0;
    std::uint8_t type = kFrameHeaders;
    while (true) {
        const std::size_t n = std::min(block.size() - off, kChunkMax);
        std::uint8_t flags = (off + n == block.size()) ? kFlagEndHeaders : 0;
        if (type == kFrameHeaders && end_stream) flags |= kFlagEndStream;
        if (!send_frame(type, flags, sid, block.data() + off, n, false)) return false;
        off += n;
        type = kFrameContinuation;
        if (off >= block.size()) break;
    }
    return true;
}

void ServerImpl::consume(std::uint32_t sid, std::size_t bytes) {
    if (bytes == 0) return;
    std::string stream_inc;
    std::string conn_inc;
    {
        std::lock_guard<std::mutex> lk(mu_);
        std::int64_t applied = static_cast<std::int64_t>(bytes);
        auto it = streams_.find(sid);
        if (it != streams_.end()) {
            StreamState& st = it->second;
            applied = std::min<std::int64_t>(applied, std::max<std::int64_t>(0, st.outstanding));
            st.outstanding -= applied;
            outstanding_total_ -= applied;
            if (outstanding_total_ < 0) outstanding_total_ = 0;
            st.credit += applied;
            if (st.credit >= static_cast<std::int64_t>(cfg_.stream_credit_batch) && !st.reset &&
                !st.local_end) {
                put_u32(stream_inc, static_cast<std::uint32_t>(st.credit));
                st.credit = 0;
            }
        }
        // The connection window is shared, so its credit is returned even when
        // the stream itself is already gone: bytes we dropped on a refused or
        // reset stream still consumed connection window, and a connection that
        // serves many short streams would otherwise starve.
        conn_credit_ += applied;
        if (conn_credit_ >= static_cast<std::int64_t>(cfg_.connection_credit_batch)) {
            put_u32(conn_inc, static_cast<std::uint32_t>(conn_credit_));
            conn_credit_ = 0;
        }
    }
    if (!stream_inc.empty()) send_frame(kFrameWindowUpdate, 0, sid, stream_inc.data(), 4, false);
    if (!conn_inc.empty()) send_frame(kFrameWindowUpdate, 0, 0, conn_inc.data(), 4, false);
    cv_.notify_all();
}

void ServerImpl::rst_stream(std::uint32_t sid, std::uint32_t code) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(sid);
        if (it == streams_.end()) return;
        outstanding_total_ -= it->second.outstanding;
        if (outstanding_total_ < 0) outstanding_total_ = 0;
        streams_.erase(it);
    }
    std::string payload;
    put_u32(payload, code);
    send_frame(kFrameRstStream, 0, sid, payload.data(), payload.size(), false);
    cv_.notify_all();
}

void ServerImpl::close_stream(std::uint32_t sid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = streams_.find(sid);
    if (it == streams_.end()) return;
    outstanding_total_ -= it->second.outstanding;
    if (outstanding_total_ < 0) outstanding_total_ = 0;
    streams_.erase(it);
    cv_.notify_all();
}

void ServerImpl::append_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid,
                              const char* payload, std::size_t len) {
    const std::size_t base = tx_.size();
    tx_.resize(base + 9 + len);
    char* dst = &tx_[base];
    dst[0] = static_cast<char>((len >> 16) & 0xFF);
    dst[1] = static_cast<char>((len >> 8) & 0xFF);
    dst[2] = static_cast<char>(len & 0xFF);
    dst[3] = static_cast<char>(type);
    dst[4] = static_cast<char>(flags);
    const std::uint32_t s = sid & 0x7FFFFFFFu;
    dst[5] = static_cast<char>((s >> 24) & 0xFF);
    dst[6] = static_cast<char>((s >> 16) & 0xFF);
    dst[7] = static_cast<char>((s >> 8) & 0xFF);
    dst[8] = static_cast<char>(s & 0xFF);
    if (len && payload) std::memcpy(dst + 9, payload, len);
}

bool ServerImpl::flush_locked() {
    if (tx_.empty()) return true;
    std::size_t off = 0;
    int stalls = 0;
    while (off < tx_.size()) {
        net::IoResult result = net::IoResult::Error;
        const int n = net::tls_write(ssl_, fd_, tx_.data() + off,
                                     static_cast<int>(tx_.size() - off), result);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            bytes_tx_ += static_cast<unsigned long long>(n);
            continue;
        }
        if (result == net::IoResult::WouldBlock) {
            net::PollFd pfd{fd_, net::kWrite, 0};
            if (net::poll_fds(&pfd, 1, 500) <= 0) {
                // 60 s without the peer accepting a single byte: the path is
                // dead, not slow. Dropping the buffer here is what lets a
                // session thread unwind instead of hanging on a write.
                if (++stalls > 120) {
                    end_reason_ = "write stalled";
                    alive_.store(false);
                    tx_.clear();
                    cv_.notify_all();
                    return false;
                }
                continue;
            }
            stalls = 0;
            continue;
        }
        end_reason_ = "write failed";
        alive_.store(false);
        tx_.clear();
        cv_.notify_all();
        return false;
    }
    tx_.clear();
    return true;
}

bool ServerImpl::flush() {
    std::lock_guard<std::mutex> lk(wmu_);
    if (!alive_.load()) return false;
    return flush_locked();
}

bool ServerImpl::send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid,
                            const char* payload, std::size_t len, bool batch) {
    std::lock_guard<std::mutex> lk(wmu_);
    if (!alive_.load()) return false;
    append_frame(type, flags, sid, payload, len);
    trace("[h2 tx] type=%u flags=0x%02x stream=%u len=%zu", type, flags, sid, len);
    // Bulk DATA is batched; everything else (SETTINGS, PING, WINDOW_UPDATE, the
    // last frame of a stream) must not wait for the next write to reach the peer.
    const bool control = (type != kFrameData);
    if (!batch || control || tx_.size() >= kTxBatch) return flush_locked();
    return true;
}

void ServerImpl::release() {
    alive_.store(false);
    cv_.notify_all();
    {
        std::lock_guard<std::mutex> lk(mu_);
        streams_.clear();
        outstanding_total_ = 0;
    }
    std::lock_guard<std::mutex> lk(wmu_);
    if (released_) return;
    released_ = true;
    if (ssl_ || fd_ != net::kInvalid) {
        // Best effort, non-blocking: tell the peer why before the socket goes.
        // No retry loop here on purpose -- a connection that is being torn down
        // must not wait for a peer that may already be gone.
        std::string payload;
        put_u32(payload, last_stream_id_ & 0x7FFFFFFFu);
        put_u32(payload, kNoError);
        tx_.clear();
        append_frame(kFrameGoAway, 0, 0, payload.data(), payload.size());
        net::IoResult ignored = net::IoResult::Error;
        net::tls_write(ssl_, fd_, tx_.data(), static_cast<int>(tx_.size()), ignored);
        tx_.clear();
        if (ssl_) {
            SSL_shutdown(ssl_);
            net::tls_free(ssl_);
            ssl_ = nullptr;
        }
        if (fd_ != net::kInvalid) {
            net::close(fd_);
            fd_ = net::kInvalid;
        }
    }
    if (bpb::log::enabled(bpb::log::kDebug)) {
        std::fprintf(stderr,
                     "[h2] connection end: reason=%s frames=%llu streams=%llu rx=%llu tx=%llu\n",
                     end_reason_, frames_, streams_opened_, bytes_rx_, bytes_tx_);
    }
}

} // namespace

std::shared_ptr<Server> create(net::socket_t fd, SSL* ssl, std::string buffered, Handlers handlers,
                               Settings settings) {
    return std::make_shared<ServerImpl>(fd, ssl, std::move(buffered), std::move(handlers), settings);
}

} // namespace bpb::proxy::h2s
