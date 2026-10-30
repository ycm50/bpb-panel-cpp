#include "proxy/session.h"
#include "crypto/crypto.h"
#include "net/tls.h"
#include "util/util.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
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
    while (sent < len) {
        net::IoResult result = net::IoResult::Error;
        int n = net::tls_write(ssl, fd, data + sent, static_cast<int>(len - sent), result);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (result == net::IoResult::WouldBlock) {
            net::PollFd pfd{fd, static_cast<short>(net::kWrite | net::kRead), 0};
            if (net::poll_fds(&pfd, 1, 10000) <= 0) return false;
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

struct Addr {
    std::string host;
    int port = 0;
};

// Parses atyp + address starting at pos (no port). Returns false when incomplete.
bool parse_atyp_addr(const std::string& buf, std::size_t& pos, Addr& addr) {
    if (pos >= buf.size()) return false;
    int atyp = static_cast<unsigned char>(buf[pos++]);
    if (atyp == 1) {
        if (pos + 4 > buf.size()) return false;
        char ip[32];
        std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u", static_cast<unsigned char>(buf[pos]),
                      static_cast<unsigned char>(buf[pos + 1]),
                      static_cast<unsigned char>(buf[pos + 2]),
                      static_cast<unsigned char>(buf[pos + 3]));
        addr.host = ip;
        pos += 4;
    } else if (atyp == 2) {
        if (pos >= buf.size()) return false;
        std::size_t len = static_cast<unsigned char>(buf[pos++]);
        if (pos + len > buf.size()) return false;
        addr.host = buf.substr(pos, len);
        pos += len;
    } else if (atyp == 3) {
        if (pos + 16 > buf.size()) return false;
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

bool parse_vless(const std::string& buf, const std::string& uuid, Addr& addr, std::size_t& header_len,
                 std::string& response_header) {
    if (buf.size() < 24) return false;
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
    if (buf.size() < pos + addons_len + 1) return false;
    pos += addons_len;
    int command = static_cast<unsigned char>(buf[pos++]);
    if (command != 1) return false;  // only TCP
    if (!read_port(buf, pos, addr)) return false;
    if (!parse_atyp_addr(buf, pos, addr)) return false;
    header_len = pos;

    response_header.push_back(static_cast<char>(version));
    response_header.push_back(0);
    return true;
}

bool parse_trojan(const std::string& buf, const std::string& password, Addr& addr,
                  std::size_t& header_len) {
    std::string hash = crypto::sha224_hex(password);
    if (buf.size() < 56 + 2) return false;
    if (buf.compare(0, 56, hash) != 0) return false;
    if (buf.compare(56, 2, "\r\n") != 0) return false;
    std::size_t pos = 58;
    if (pos >= buf.size()) return false;
    int command = static_cast<unsigned char>(buf[pos++]);
    if (command != 1) return false;
    if (!parse_atyp_addr(buf, pos, addr)) return false;
    if (!read_port(buf, pos, addr)) return false;
    if (buf.compare(pos, 2, "\r\n") != 0) return false;
    header_len = pos + 2;
    return true;
}

// Reads one websocket frame payload into out. Returns false on close/error.
enum class FrameState { Ok, Closed, Error };

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
            net::PollFd pfd{fd, net::kRead, 0};
            if (net::poll_fds(&pfd, 1, 60000) <= 0) return FrameState::Error;
            continue;
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

void session_loop(SSL* client_ssl, socket_t client, const std::string& protocol,
                  const SessionConfig& config) {
    std::string pending;
    std::string handshake_buffer;
    bool connected = false;
    socket_t upstream = net::kInvalid;
    bool vless = (protocol == "vl");
    std::string response_header;

    auto try_connect = [&](const std::string& data) -> bool {
        Addr addr;
        std::size_t header_len = 0;
        bool ok = vless ? parse_vless(data, config.vl_uuid, addr, header_len, response_header)
                        : parse_trojan(data, config.tr_pass, addr, header_len);
        if (!ok) return false;

        Addr target;
        resolve_target(addr.host, addr.port, config, target);
        upstream = connect_tcp(target.host, target.port, 5000);
        if (upstream == net::kInvalid) return false;

        if (!response_header.empty()) {
            if (!ws_send(client_ssl, client, response_header.data(), response_header.size())) return false;
        }
        if (data.size() > header_len) {
            std::string rest = data.substr(header_len);
            if (!send_all(nullptr, upstream, rest.data(), rest.size())) return false;
        }
        connected = true;
        return true;
    };

    while (true) {
        net::PollFd fds[2];
        std::size_t count = 0;
        bool client_pending = (net::tls_pending(client_ssl) > 0);
        if (client_pending) {
            fds[0] = {client, net::kRead, net::kRead};
            fds[1] = {upstream, net::kRead, 0};
            count = 2;
        } else {
            fds[0] = {client, net::kRead, 0};
            fds[1] = {net::kInvalid, 0, 0};
            count = 1;
            if (connected && upstream != net::kInvalid) {
                fds[1] = {upstream, net::kRead, 0};
                count = 2;
            }
            int rc = net::poll_fds(fds, count, 60000);
            if (rc <= 0) break;
        }

        if (fds[0].revents & (net::kRead | net::kError)) {
            std::string payload;
            int opcode = 0;
            FrameState state = read_frame(client_ssl, client, pending, payload, opcode);
            if (state != FrameState::Ok) {
                if (!connected && !handshake_buffer.empty()) {
                    // try again with what we have
                    if (!try_connect(handshake_buffer)) break;
                    continue;
                }
                break;
            }
            if (opcode == 0x8) break;              // close
            if (opcode == 0x9) {                   // ping
                ws_send(client_ssl, client, payload.data(), payload.size(), 0xA);
                continue;
            }
            if (opcode == 0xA) continue;           // pong

            if (!connected) {
                handshake_buffer += payload;
                if (!try_connect(handshake_buffer)) {
                    if (handshake_buffer.size() > 64) break;
                    continue;
                }
                handshake_buffer.clear();
            } else if (!payload.empty()) {
                if (!send_all(nullptr, upstream, payload.data(), payload.size())) break;
            }
        }

        if (connected && count > 1 && (fds[1].revents & (net::kRead | net::kError))) {
            char buf[kChunk];
            int n = static_cast<int>(::recv(upstream, buf, sizeof(buf), 0));
            if (n <= 0) break;
            if (!ws_send(client_ssl, client, buf, static_cast<std::size_t>(n))) break;
        }
    }

    if (upstream != net::kInvalid) net::close(upstream);
    if (client_ssl) {
        SSL_shutdown(client_ssl);
        net::tls_free(client_ssl);
    }
    if (client != net::kInvalid) net::close(client);
}

} // namespace

void run_ws_session(net::socket_t client_fd, SSL* client_ssl, std::string accept_key,
                    std::string path, SessionConfig config) {
    std::string protocol = path;
    if (!protocol.empty() && protocol[0] == '/') protocol = protocol.substr(1);
    auto slash = protocol.find('/');
    if (slash != std::string::npos) protocol = protocol.substr(0, slash);

    std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: " + accept_key + "\r\n\r\n";
    if (!send_all(client_ssl, client_fd, response.data(), response.size())) {
        if (client_ssl) net::tls_free(client_ssl);
        net::close(client_fd);
        return;
    }
    std::thread([client_fd, client_ssl, protocol, config]() {
        session_loop(client_ssl, client_fd, protocol, config);
    }).detach();
}

} // namespace bpb::proxy