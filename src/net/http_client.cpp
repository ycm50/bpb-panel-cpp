#include "net/http_client.h"
#include "net/net.h"
#include "util/util.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace bpb::net::httpc {

std::string Response::header(const std::string& name) const {
    auto it = headers.find(to_lower(name));
    return it == headers.end() ? std::string() : it->second;
}

bool parse_url(const std::string& url, Url& out, std::string& error) {
    std::size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        error = "missing scheme";
        return false;
    }
    out.scheme = to_lower(url.substr(0, scheme_end));
    if (out.scheme != "http" && out.scheme != "https") {
        error = "unsupported scheme: " + out.scheme;
        return false;
    }
    std::string rest = url.substr(scheme_end + 3);
    std::size_t slash = rest.find('/');
    std::string authority = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    out.path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    if (out.path.empty()) out.path = "/";

    std::size_t at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);

    if (!authority.empty() && authority[0] == '[') {
        std::size_t close = authority.find(']');
        if (close == std::string::npos) {
            error = "bad ipv6 host";
            return false;
        }
        out.host = authority.substr(1, close - 1);
        out.port = (close + 1 < authority.size() && authority[close + 1] == ':')
                       ? std::atoi(authority.c_str() + close + 2)
                       : ((out.scheme == "https") ? 443 : 80);
        return true;
    }

    std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        out.host = authority.substr(0, colon);
        out.port = std::atoi(authority.c_str() + colon + 1);
    } else {
        out.host = authority;
        out.port = (out.scheme == "https") ? 443 : 80;
    }
    if (out.host.empty()) {
        error = "empty host";
        return false;
    }
    return true;
}

static void set_socket_timeout(net::socket_t fd, int timeout_ms) {
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

static net::socket_t connect_tcp(const std::string& host, int port, int timeout_ms, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;  // no AAAA when the host has no IPv6 address
    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        error = "dns resolution failed for " + host;
        return net::kInvalid;
    }

    net::socket_t fd = net::kInvalid;
    for (addrinfo* p = res; p; p = p->ai_next) {
        net::socket_t s = static_cast<net::socket_t>(::socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (s == net::kInvalid) continue;

        bool ok = true;
#ifdef _WIN32
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
#else
        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
        int rc = ::connect(s, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen));
        if (rc != 0) {
            int err = net::last_error();
            if (!net::would_block(err)) {
                ok = false;
            } else {
                net::PollFd pfd{s, net::kWrite, 0};
                int pr = net::poll_fds(&pfd, 1, timeout_ms);
                if (pr <= 0) {
                    ok = false;
                } else {
                    int soerr = 0;
                    socklen_t l = sizeof(soerr);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &l);
                    if (soerr != 0) ok = false;
                }
            }
        }
        if (ok) {
            net::set_nonblocking(s);
#ifdef _WIN32
            u_long zero = 0;
            ioctlsocket(s, FIONBIO, &zero);
#else
            fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) & ~O_NONBLOCK);
#endif
            net::set_nodelay(s);
            set_socket_timeout(s, timeout_ms);
            fd = s;
            break;
        }
        net::close(s);
    }
    freeaddrinfo(res);
    if (fd == net::kInvalid && error.empty()) error = "connect failed to " + host;
    return fd;
}

static std::string env_first(const char* a, const char* b) {
    const char* v = std::getenv(a);
    if (!v || !*v) v = std::getenv(b);
    return v ? std::string(v) : std::string();
}

static std::string proxy_for(const std::string& scheme) {
    if (scheme == "https") {
        std::string p = env_first("HTTPS_PROXY", "https_proxy");
        if (!p.empty()) return p;
    }
    return env_first("HTTP_PROXY", "http_proxy");
}

// Opens a tunnel through an HTTP proxy using CONNECT and returns a socket ready for TLS.
static net::socket_t connect_via_proxy(const std::string& proxy_url, const std::string& host,
                                       int port, int timeout_ms, std::string& error) {
    Url p;
    if (!parse_url(proxy_url, p, error)) return net::kInvalid;
    net::socket_t fd = connect_tcp(p.host, p.port, timeout_ms, error);
    if (fd == net::kInvalid) return net::kInvalid;

    std::string authority = host + ":" + std::to_string(port);
    std::string req = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
                      "\r\nUser-Agent: bpb-native\r\n\r\n";
    if (::send(fd, req.data(), static_cast<int>(req.size()), 0) <= 0) {
        error = "proxy connect write failed";
        net::close(fd);
        return net::kInvalid;
    }
    std::string buf;
    char tmp[1024];
    while (buf.find("\r\n\r\n") == std::string::npos && buf.size() < 16384) {
        int n = static_cast<int>(::recv(fd, tmp, sizeof(tmp), 0));
        if (n <= 0) {
            error = "proxy connect read failed";
            net::close(fd);
            return net::kInvalid;
        }
        buf.append(tmp, static_cast<std::size_t>(n));
    }
    if (buf.find(" 200 ") == std::string::npos) {
        error = "proxy refused CONNECT: " + buf.substr(0, 80);
        net::close(fd);
        return net::kInvalid;
    }
    return fd;
}

static SSL_CTX* g_ctx = nullptr;

static SSL_CTX* tls_context(std::string& error) {
    if (g_ctx) return g_ctx;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        error = "SSL_CTX_new failed";
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    const char* cafile = std::getenv("SSL_CERT_FILE");
    if (cafile && *cafile) {
        if (SSL_CTX_load_verify_locations(ctx, cafile, nullptr) != 1) {
            SSL_CTX_set_default_verify_paths(ctx);
        }
    } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    g_ctx = ctx;
    return ctx;
}

static bool read_all_until_close(SSL* ssl, net::socket_t fd, bool use_tls, std::string& out,
                                 std::string& error) {
    char buf[16384];
    while (true) {
        int n;
        if (use_tls) {
            n = SSL_read(ssl, buf, sizeof(buf));
            if (n <= 0) {
                int e = SSL_get_error(ssl, n);
                if (e == SSL_ERROR_ZERO_RETURN) return true;
                if (e == SSL_ERROR_SYSCALL && n == 0) return true;
                error = "tls read failed";
                return false;
            }
        } else {
            n = static_cast<int>(::recv(fd, buf, sizeof(buf), 0));
            if (n == 0) return true;
            if (n < 0) {
                error = "socket read failed";
                return false;
            }
        }
        out.append(buf, static_cast<std::size_t>(n));
        if (out.size() > 8 * 1024 * 1024) {
            error = "response too large";
            return false;
        }
    }
}

static std::string dechunk(const std::string& body) {
    std::string out;
    std::size_t pos = 0;
    while (pos < body.size()) {
        std::size_t eol = body.find("\r\n", pos);
        if (eol == std::string::npos) break;
        std::string size_line = body.substr(pos, eol - pos);
        std::size_t semi = size_line.find(';');
        if (semi != std::string::npos) size_line = size_line.substr(0, semi);
        std::size_t len = static_cast<std::size_t>(std::strtoul(size_line.c_str(), nullptr, 16));
        if (len == 0) break;
        std::size_t start = eol + 2;
        if (start + len > body.size()) break;
        out.append(body, start, len);
        pos = start + len + 2;
    }
    return out;
}

bool request(const std::string& method,
             const std::string& url,
             const std::string& body,
             const Headers& headers,
             Response& out,
             std::string& error,
             int timeout_ms) {
    Url u;
    if (!parse_url(url, u, error)) return false;

    bool use_tls = (u.scheme == "https");
    std::string proxy = proxy_for(u.scheme);
    net::socket_t fd = proxy.empty() ? connect_tcp(u.host, u.port, timeout_ms, error)
                                     : connect_via_proxy(proxy, u.host, u.port, timeout_ms, error);
    if (fd == net::kInvalid) return false;

    SSL* ssl = nullptr;
    SSL_CTX* ctx = nullptr;
    if (use_tls) {
        ctx = tls_context(error);
        if (!ctx) {
            net::close(fd);
            return false;
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, static_cast<int>(fd));
        if (!u.host.empty()) {
            SSL_set_tlsext_host_name(ssl, u.host.c_str());
            SSL_set1_host(ssl, u.host.c_str());
        }
        SSL_set_connect_state(ssl);
        if (SSL_connect(ssl) != 1) {
            error = std::string("tls handshake failed: ") + ERR_error_string(ERR_get_error(), nullptr);
            SSL_free(ssl);
            net::close(fd);
            return false;
        }
    }

    std::string req = method + " " + u.path + " HTTP/1.1\r\n";
    req += "Host: " + u.host + (u.port == 80 || u.port == 443 ? "" : ":" + std::to_string(u.port)) + "\r\n";
    req += "User-Agent: bpb-native/1.0.0\r\nAccept-Encoding: identity\r\nConnection: close\r\n";
    bool has_ct = false;
    bool has_accept = false;
    for (auto& [k, v] : headers) {
        std::string lk = to_lower(k);
        if (lk == "content-type") has_ct = true;
        if (lk == "accept") has_accept = true;
        req += k + ": " + v + "\r\n";
    }
    if (!has_accept) req += "Accept: */*\r\n";
    if (!body.empty()) {
        if (!has_ct) req += "Content-Type: application/json\r\n";
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    req += "\r\n";
    req += body;

    auto write_all = [&](const std::string& data) -> bool {
        std::size_t sent = 0;
        while (sent < data.size()) {
            int n;
            if (use_tls) {
                n = SSL_write(ssl, data.data() + sent, static_cast<int>(data.size() - sent));
            } else {
                n = static_cast<int>(::send(fd, data.data() + sent, static_cast<int>(data.size() - sent), 0));
            }
            if (n <= 0) return false;
            sent += static_cast<std::size_t>(n);
        }
        return true;
    };

    if (!write_all(req)) {
        error = "request write failed";
        if (ssl) SSL_free(ssl);
        net::close(fd);
        return false;
    }

    std::string raw;
    bool ok = read_all_until_close(ssl, fd, use_tls, raw, error);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    net::close(fd);
    if (!ok) return false;

    std::size_t head_end = raw.find("\r\n\r\n");
    if (head_end == std::string::npos) {
        error = "malformed http response";
        return false;
    }
    std::string head = raw.substr(0, head_end);
    std::string body_raw = raw.substr(head_end + 4);
    auto lines = split(head, '\n');
    if (lines.empty()) {
        error = "empty http response";
        return false;
    }
    auto status_parts = split(trim(lines[0]), ' ');
    out.status = status_parts.size() > 1 ? std::atoi(status_parts[1].c_str()) : 0;
    for (std::size_t i = 1; i < lines.size(); ++i) {
        std::string line = lines[i];
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = to_lower(trim(line.substr(0, colon)));
        out.headers[name] = trim(line.substr(colon + 1));
    }
    if (to_lower(out.headers["transfer-encoding"]).find("chunked") != std::string::npos) {
        out.body = dechunk(body_raw);
    } else {
        out.body = body_raw;
        auto it = out.headers.find("content-length");
        if (it != out.headers.end()) {
            std::size_t len = static_cast<std::size_t>(std::strtoul(it->second.c_str(), nullptr, 10));
            if (out.body.size() > len) out.body.resize(len);
        }
    }
    return true;
}

bool get(const std::string& url, Response& out, std::string& error, int timeout_ms,
         const Headers& headers) {
    return request("GET", url, "", headers, out, error, timeout_ms);
}

bool post(const std::string& url, const std::string& body, Response& out, std::string& error,
          int timeout_ms, const Headers& headers) {
    return request("POST", url, body, headers, out, error, timeout_ms);
}

} // namespace bpb::net::httpc
