#include "http/http.h"
#include "net/tls.h"
#include "util/util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

namespace bpb::http {

static constexpr std::size_t kMaxHeader = 64 * 1024;
static constexpr std::size_t kMaxBody = 16 * 1024 * 1024;
static constexpr int kIdleTimeoutMs = 60000;

std::string Request::header(std::string_view name) const {
    auto it = headers.find(std::string(name));
    return it == headers.end() ? std::string() : it->second;
}

std::map<std::string, std::string> Request::params() const { return parse_query(query); }

void Response::set(std::string name, std::string value) {
    headers.emplace_back(std::move(name), std::move(value));
}

Response Response::json(int status, std::string body) {
    Response r;
    r.status = status;
    r.set("Content-Type", "application/json");
    r.body = std::move(body);
    return r;
}

Response Response::text(int status, std::string body) {
    Response r;
    r.status = status;
    r.set("Content-Type", "text/plain; charset=utf-8");
    r.body = std::move(body);
    return r;
}

Response Response::html(std::string body) {
    Response r;
    r.status = 200;
    r.set("Content-Type", "text/html; charset=utf-8");
    r.set("Cache-Control", "no-store");
    r.body = std::move(body);
    return r;
}

Response Response::redirect(std::string location) {
    Response r;
    r.status = 302;
    r.set("Location", std::move(location));
    r.body.clear();
    return r;
}

Server::Server() = default;
Server::~Server() {
    for (auto& c : conns_) {
        if (!c) continue;
        if (c->ssl) net::tls_free(c->ssl);
        if (c->fd != net::kInvalid) net::close(c->fd);
    }
    if (listener_ != net::kInvalid) net::close(listener_);
}

bool Server::enable_tls(const std::string& cert_path, const std::string& key_path, std::string& error) {
    if (!net::tls_init_server(cert_path, key_path, error)) return false;
    tls_on_ = true;
    return true;
}

bool Server::listen(const std::string& host, int port, std::string& error) {
    listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener_ == net::kInvalid) {
        error = "socket() failed: " + net::error_string(net::last_error());
        return false;
    }
    net::set_reuseaddr(listener_);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<unsigned short>(port));
    if (host.empty() || host == "0.0.0.0") addr.sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        error = "invalid listen host: " + host;
        return false;
    }

    if (::bind(listener_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        error = "bind() failed: " + net::error_string(net::last_error());
        return false;
    }
    if (::listen(listener_, 512) != 0) {
        error = "listen() failed: " + net::error_string(net::last_error());
        return false;
    }
    net::set_nonblocking(listener_);
    return true;
}

void Server::now(std::int64_t& out) const {
    out = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now().time_since_epoch())
              .count();
}

void Server::accept_new() {
    while (true) {
        sockaddr_in addr{};
#ifdef _WIN32
        int len = sizeof(addr);
#else
        socklen_t len = sizeof(addr);
#endif
        net::socket_t fd = ::accept(listener_, reinterpret_cast<sockaddr*>(&addr), &len);
        if (fd == net::kInvalid) return;
        net::set_nonblocking(fd);
        net::set_nodelay(fd);
        auto c = std::make_unique<Conn>();
        c->fd = fd;
        now(c->last_active);
        if (tls_on_) {
            std::string error;
            c->ssl = net::tls_new_server(fd, error);
            if (!c->ssl) {
                net::close(fd);
                continue;
            }
            c->handshaking = true;
        }
        conns_.push_back(std::move(c));
    }
}

bool Server::read_into(Conn& c) {
    char buf[16384];
    while (true) {
        net::IoResult result = net::IoResult::Error;
        int n = net::tls_read(c.ssl, c.fd, buf, static_cast<int>(sizeof(buf)), result);
        if (n > 0) {
            now(c.last_active);
            c.in.append(buf, static_cast<std::size_t>(n));
            if (c.in.size() > kMaxHeader + kMaxBody) {
                Response r = Response::text(413, "Payload Too Large");
                c.out += "HTTP/1.1 413 Payload Too Large\r\nContent-Length: " + std::to_string(r.body.size()) + "\r\nConnection: close\r\n\r\n" + r.body;
                c.close_after_write = true;
                return true;
            }
            continue;
        }
        if (result == net::IoResult::WouldBlock) return true;
        if (result == net::IoResult::Closed) {
            // End of the peer's write side. Do NOT drop the connection: a
            // complete request may already be buffered (a GET with an
            // immediately half-closed socket, which is exactly what the tunnel
            // relay produces for bodyless requests). Mark it and let process()
            // answer, then close after the response is written.
            c.peer_closed = true;
            return true;
        }
        return false;
    }
}

bool Server::handshake_step(Conn& c) {
    if (!c.ssl) return false;
    int rc = SSL_accept(c.ssl);
    if (rc == 1) {
        c.handshaking = false;
        return true;
    }
    int err = SSL_get_error(c.ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return true;
    return false;
}

static bool parse_request(std::string& in, Request& req) {
    auto head_end = in.find("\r\n\r\n");
    if (head_end == std::string::npos) return false;

    std::string head = in.substr(0, head_end);
    auto lines = split(head, '\n');
    if (lines.empty()) return false;
    auto first = trim(lines[0]);
    auto parts = split(first, ' ');
    if (parts.size() < 2) return false;
    req.method = parts[0];
    req.target = parts[1];
    req.version = parts.size() > 2 ? parts[2] : "HTTP/1.1";

    auto qpos = req.target.find('?');
    if (qpos == std::string::npos) {
        req.path = req.target;
    } else {
        req.path = req.target.substr(0, qpos);
        req.query = req.target.substr(qpos + 1);
    }

    for (std::size_t i = 1; i < lines.size(); ++i) {
        auto line = lines[i];
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = to_lower(trim(line.substr(0, colon)));
        std::string value = trim(line.substr(colon + 1));
        if (!name.empty()) req.headers[name] = value;
    }

    std::size_t body_len = 0;
    auto it = req.headers.find("content-length");
    if (it != req.headers.end()) body_len = static_cast<std::size_t>(std::stoull(it->second));
    if (in.size() < head_end + 4 + body_len) return false;
    req.body = in.substr(head_end + 4, body_len);
    in.erase(0, head_end + 4 + body_len);
    return true;
}

void Server::process(Conn& c) {
    while (true) {
        Request req;
        if (!parse_request(c.in, req)) return;
        bool keep_alive = true;
        auto conn_hdr = to_lower(req.header("connection"));
        if (req.version == "HTTP/1.0" || conn_hdr.find("close") != std::string::npos) keep_alive = false;

        // WebSocket upgrade. A plain client sends Upgrade: websocket; the
        // Cloudflare edge instead marks the stream with
        // cf-cloudflared-proxy-connection-upgrade: websocket and does NOT
        // forward the standard header (cloudflared re-adds it internally).
        // Accept both, otherwise a tunnel-fronted request is routed as ordinary
        // HTTP and 404s.
        auto upgrade = to_lower(req.header("upgrade"));
        if (upgrade.empty() &&
            to_lower(req.header("cf-cloudflared-proxy-connection-upgrade")) == "websocket") {
            upgrade = "websocket";
        }
        if (upgrade == "websocket" && ws_handler_) {
            std::string key = req.header("sec-websocket-key");
            std::string accept_src = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            unsigned char digest[SHA_DIGEST_LENGTH];
            SHA1(reinterpret_cast<const unsigned char*>(accept_src.data()), accept_src.size(), digest);
            std::string accept_key = base64_encode(digest, SHA_DIGEST_LENGTH);
            net::socket_t fd = c.fd;
            SSL* ssl = c.ssl;
            c.fd = net::kInvalid;
            c.ssl = nullptr;
            c.detached = true;
            ws_handler_(fd, ssl, req, accept_key);
            return;
        }

        Response res;
        if (handler_) {
            try {
                res = handler_(req);
            } catch (const std::exception& e) {
                res = Response::text(500, std::string("Internal Server Error: ") + e.what());
                keep_alive = false;
            }
        } else {
            res = Response::text(500, "No handler");
            keep_alive = false;
        }

        std::string out;
        out.reserve(res.body.size() + 256);
        out += "HTTP/1.1 " + std::to_string(res.status) + " " + "OK" + "\r\n";
        bool has_len = false;
        bool has_date = false;
        for (auto& [k, v] : res.headers) {
            std::string lk = to_lower(k);
            if (lk == "content-length") has_len = true;
            if (lk == "date") has_date = true;
            out += k + ": " + v + "\r\n";
        }
        if (!has_date) out += "Date: " + iso_time_now() + "\r\n";
        if (!has_len) out += "Content-Length: " + std::to_string(res.body.size()) + "\r\n";
        if (!keep_alive || res.close) out += "Connection: close\r\n";
        else out += "Connection: keep-alive\r\n";
        out += "\r\n";
        out += res.body;

        c.out += out;
        // A half-closed peer cannot send another request, so this response is
        // the last one on the connection.
        if (!keep_alive || res.close || c.peer_closed) c.close_after_write = true;
        flush(c);
        if (c.detached) return;
        // Closing connection: there is nothing left to parse, but any tail still
        // in c.out must be flushed by run()'s write arm before the socket is
        // dropped. Returning here is safe *because* run() keeps such a
        // connection registered for POLLOUT until c->out is empty.
        if (c.close_after_write) return;
        // Nothing more can arrive from a half-closed peer.
        if (c.peer_closed) return;
        if (c.in.empty()) return;
    }
}

void Server::flush(Conn& c) {
    // Cap one write at 16 KiB. Passing the whole 1 MiB body to SSL_write makes
    // OpenSSL encode dozens of records before returning, and on a non-blocking
    // socket a single WANT_WRITE then loses all that work. Chunking keeps each
    // step atomic and lets the poll loop interleave with other connections.
    constexpr std::size_t kWriteChunk = 16 * 1024;
    while (!c.out.empty()) {
        net::IoResult result = net::IoResult::Error;
        const int want = static_cast<int>(std::min(c.out.size(), kWriteChunk));
        int n = net::tls_write(c.ssl, c.fd, c.out.data(), want, result);
        if (n > 0) {
            c.out.erase(0, static_cast<std::size_t>(n));
            continue;
        }
        if (result == net::IoResult::WouldBlock) return;
        c.close_after_write = true;
        return;
    }
}

void Server::drop(std::size_t index) {
    auto& c = conns_[index];
    if (c) {
        if (c->ssl) net::tls_free(c->ssl);
        if (c->fd != net::kInvalid) net::close(c->fd);
    }
    conns_.erase(conns_.begin() + static_cast<std::ptrdiff_t>(index));
}

void Server::run() {
    running_ = true;
    std::vector<net::PollFd> pfds;
    std::vector<std::size_t> map;
    while (running_) {
        pfds.clear();
        map.clear();
        pfds.push_back({listener_, net::kRead, 0});
        map.push_back(static_cast<std::size_t>(-1));
        for (std::size_t i = 0; i < conns_.size(); ++i) {
            auto& c = conns_[i];
            if (!c || c->detached || c->fd == net::kInvalid) continue;
            // A half-closed peer can never send again. Keeping it in the poll
            // set made poll() return POLLIN every iteration (nothing is read any
            // more), which burned ~50% of a core and left the socket in
            // CLOSE-WAIT forever. Its only remaining work is flushing the
            // response, handled by the write arm below.
            if (c->peer_closed && c->out.empty()) continue;
            short ev = net::kRead;
            if (!c->out.empty()) ev |= net::kWrite;
            if (c->ssl && net::tls_wants_write(c->ssl)) ev |= net::kWrite;
            pfds.push_back({c->fd, ev, 0});
            map.push_back(i);
        }
        // Short poll when any connection still has a request already buffered
        // (a keep-alive client that pipelined) or a response tail to push, so
        // the next round happens immediately instead of after the idle tick.
        int pollWait = 1000;
        for (auto& cc : conns_) {
            if (!cc || cc->detached) continue;
            if (!cc->in.empty() || !cc->out.empty()) { pollWait = 1; break; }
        }
        int rc = net::poll_fds(pfds.data(), pfds.size(), pollWait);
        if (rc < 0) {
            int err = net::last_error();
            if (err != 0 && !net::would_block(err)) continue;
            continue;
        }
        std::vector<std::size_t> dead;
        for (std::size_t k = 0; k < pfds.size(); ++k) {
            if (pfds[k].revents == 0) continue;
            if (map[k] == static_cast<std::size_t>(-1)) {
                accept_new();
                continue;
            }
            std::size_t idx = map[k];
            if (idx >= conns_.size()) continue;
            auto& c = conns_[idx];
            if (!c) continue;
            if (pfds[k].revents & net::kError) {
                dead.push_back(idx);
                continue;
            }
            if (c->handshaking) {
                if (!handshake_step(*c)) {
                    dead.push_back(idx);
                    continue;
                }
                if (c->handshaking) continue;
            }
            if (pfds[k].revents & net::kWrite) flush(*c);
            if (pfds[k].revents & (net::kRead | net::kWrite)) {
                if (!c->close_after_write && !c->peer_closed) {
                    if (!read_into(*c)) { dead.push_back(idx); continue; }
                }
                process(*c);
                // Close only after the tail is actually on the wire; otherwise
                // the client waits for a response we still hold in c.out.
                if (c->close_after_write && c->out.empty()) dead.push_back(idx);
            }
        }
        // idle timeout
        std::int64_t t;
        now(t);
        for (std::size_t i = 0; i < conns_.size(); ++i) {
            auto& c = conns_[i];
            if (!c || c->detached || c->fd == net::kInvalid) continue;
            // Peer closed and the response is out: nothing left to do.
            if (c->peer_closed && c->out.empty()) {
                dead.push_back(i);
                continue;
            }
            if (c->out.empty() && !c->in.empty() && t - c->last_active > kIdleTimeoutMs) dead.push_back(i);
        }
        std::sort(dead.begin(), dead.end());
        dead.erase(std::unique(dead.begin(), dead.end()), dead.end());
        for (auto it = dead.rbegin(); it != dead.rend(); ++it) {
            if (*it < conns_.size()) drop(*it);
        }
    }
}

} // namespace bpb::http
