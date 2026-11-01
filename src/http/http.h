#pragma once
#include "net/net.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

typedef struct ssl_st SSL;

namespace bpb::http {

struct Request {
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::string version;
    std::map<std::string, std::string> headers; // lowercase keys
    std::string body;
    std::string header(std::string_view name) const;
    std::map<std::string, std::string> params() const;
};

struct Response {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool close = false;

    void set(std::string name, std::string value);
    static Response json(int status, std::string body);
    static Response text(int status, std::string body);
    static Response html(std::string body);
    static Response redirect(std::string location);
};

class Server {
public:
    using Handler = std::function<Response(const Request&)>;
    using WsHandler = std::function<void(net::socket_t fd, SSL* ssl, const Request&, const std::string& accept_key)>;

    Server();
    ~Server();

    void set_handler(Handler h) { handler_ = std::move(h); }
    void set_ws_handler(WsHandler h) { ws_handler_ = std::move(h); }
    bool enable_tls(const std::string& cert_path, const std::string& key_path, std::string& error);
    bool listen(const std::string& host, int port, std::string& error);
    void run();
    void stop() { running_ = false; }

private:
    struct Conn {
        net::socket_t fd = net::kInvalid;
        SSL* ssl = nullptr;
        bool handshaking = false;
        std::string in;
        std::string out;
        bool close_after_write = false;
        bool detached = false;
        // The peer half-closed (or fully closed) its side. Any request already
        // buffered must still be answered -- cloudflared and curl both send a
        // complete GET and then shutdown(SHUT_WR) to signal "no body".
        bool peer_closed = false;
        std::int64_t last_active = 0;
    };

    void accept_new();
    bool handshake_step(Conn& c);
    bool read_into(Conn& c);
    void process(Conn& c);
    void flush(Conn& c);
    void drop(std::size_t index);
    void now(std::int64_t& out) const;

    net::socket_t listener_ = net::kInvalid;
    Handler handler_;
    WsHandler ws_handler_;
    std::vector<std::unique_ptr<Conn>> conns_;
    bool running_ = false;
    bool tls_on_ = false;
};

} // namespace bpb::http
