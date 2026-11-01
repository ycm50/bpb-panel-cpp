#include "inbound/inbound.h"

#include "net/tls.h"
#include "util/log.h"

#include <openssl/ssl.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace bpb::inbound {

// Each implementation defines one of these at file scope (outside any anonymous
// namespace, or the symbol would be internal). Only the files selected by
// BPB_INBOUNDS are compiled, so the macros below are what actually decides the
// table. Adding a protocol means: write proto/<name>_ws.cpp, define
// <name>_inbound, add the name to BPB_ALL_INBOUNDS in CMakeLists.txt.
#ifdef BPB_HAVE_VLESS
extern const Inbound vless_inbound;
#endif
#ifdef BPB_HAVE_TROJAN
extern const Inbound trojan_inbound;
#endif
#ifdef BPB_HAVE_SHADOWSOCKS
extern const Inbound shadowsocks_inbound;
#endif
#ifdef BPB_HAVE_VMESS
extern const Inbound vmess_inbound;
#endif

const std::vector<const Inbound*>& all() {
    static const std::vector<const Inbound*> table = {
#ifdef BPB_HAVE_VLESS
        &vless_inbound,
#endif
#ifdef BPB_HAVE_TROJAN
        &trojan_inbound,
#endif
#ifdef BPB_HAVE_SHADOWSOCKS
        &shadowsocks_inbound,
#endif
#ifdef BPB_HAVE_VMESS
        &vmess_inbound,
#endif
    };
    return table;
}

const Inbound* by_path(std::string_view segment, const bpb::proxy::SessionConfig& config) {
    for (const Inbound* in : all()) {
        // A credential-derived path (VMess "<uuid>-vm") is only known at
        // runtime, so those entries carry a matcher instead of a constant.
        if (in->match) {
            if (in->match(segment, config)) return in;
        } else if (in->path && segment == in->path) {
            return in;
        }
    }
    return nullptr;
}

const Inbound* by_id(std::string_view id) {
    for (const Inbound* in : all()) {
        if (id == in->id) return in;
    }
    return nullptr;
}

bool has(std::string_view id) { return by_id(id) != nullptr; }

std::string id_list() {
    std::string out;
    for (const Inbound* in : all()) {
        if (!out.empty()) out += ',';
        out += in->id;
    }
    return out;
}

std::string path_list() {
    std::string out;
    for (const Inbound* in : all()) {
        if (!out.empty()) out += ',';
        out += '/';
        // Dynamic entries have no constant path; name the shape instead.
        out += in->path ? in->path : "<uuid>-vm";
    }
    return out;
}

std::string path_segment(std::string_view path) {
    const std::size_t q = path.find('?');
    if (q != std::string_view::npos) path = path.substr(0, q);
    while (!path.empty() && path.front() == '/') path.remove_prefix(1);
    const std::size_t slash = path.find('/');
    if (slash != std::string_view::npos) path = path.substr(0, slash);
    return std::string(path);
}

namespace {

// Sends a short, fixed reply. The response is a few dozen bytes, so a plain
// write loop is enough; SSL_write can return WANT_READ/WRITE but never for a
// reply this small on a healthy connection, so a short write is just dropped.
void send_small(SSL* ssl, bpb::net::socket_t fd, const char* data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        int n = ssl ? SSL_write(ssl, data + off, static_cast<int>(len - off))
                    : static_cast<int>(::send(fd, data + off, static_cast<int>(len - off), 0));
        if (n <= 0) return;
        off += static_cast<std::size_t>(n);
    }
}

} // namespace

bool is_local_target(std::string_view host) {
    if (host.empty()) return false;
    if (host == "localhost" || host == "127.0.0.1" || host == "::1") return true;
    if (host.size() > 10 && host.compare(host.size() - 10, 10, ".localhost") == 0) return true;

    std::string text(host);
    if (!text.empty() && text.front() == '[' && text.back() == ']') {
        text = text.substr(1, text.size() - 2);
    }

    unsigned char v4[4];
    if (::inet_pton(AF_INET, text.c_str(), v4) == 1) {
        if (v4[0] == 127) return true;                            // loopback
        if (v4[0] == 10) return true;                             // 10/8
        if (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) return true;  // 172.16/12
        if (v4[0] == 192 && v4[1] == 168) return true;             // 192.168/16
        if (v4[0] == 169 && v4[1] == 254) return true;             // link-local
        return false;
    }
    unsigned char v6[16];
    if (::inet_pton(AF_INET6, text.c_str(), v6) == 1) {
        if ((v6[0] & 0xFE) == 0xFC) return true;                  // fc00::/7
        if (v6[0] == 0xFE && (v6[1] & 0xC0) == 0x80) return true;  // fe80::/10
        bool loop = true;
        for (int i = 0; i < 15; ++i) {
            if (v6[i] != 0) { loop = false; break; }
        }
        if (loop && v6[15] == 1) return true;                      // ::1
    }
    return false;
}

void reject(bpb::net::socket_t fd, SSL* ssl) {
    // The request never became a WebSocket, so answer as plain HTTP/1.1 and hang
    // up. Anything else would make a client wait for an upgrade that never comes.
    static const char kNotFound[] =
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    send_small(ssl, fd, kNotFound, sizeof(kNotFound) - 1);
    if (ssl) {
        SSL_shutdown(ssl);
        bpb::net::tls_free(ssl);
    }
    bpb::net::close(fd);
}

} // namespace bpb::inbound
