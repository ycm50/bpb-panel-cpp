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
    // Takes the connection over for transports that are not one-request-one-
    // response: XHTTP's downlink GET streams for the whole session, gRPC keeps
    // an HTTP/2 connection alive. The callback owns fd/ssl from here on (write
    // the status line itself, then close). Returns false when the request is not
    // for it, and the server continues with the normal handler.
    using Takeover = std::function<bool(net::socket_t fd, SSL* ssl, const Request&)>;
    // Same idea, but for protocols that never send an HTTP/1.1 request head at
    // all: HTTP/2 clients open with the connection preface. Called with the
    // bytes already buffered; returning true takes the connection over.
    using PreTakeover =
        std::function<bool(net::socket_t fd, SSL* ssl, const std::string& buffered)>;

    Server();
    ~Server();

    void set_handler(Handler h) { handler_ = std::move(h); }
    void set_ws_handler(WsHandler h) { ws_handler_ = std::move(h); }
    void set_takeover(Takeover t) { takeover_ = std::move(t); }
    void set_pre_takeover(PreTakeover t) { pre_takeover_ = std::move(t); }
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
    Takeover takeover_;
    PreTakeover pre_takeover_;
    std::vector<std::unique_ptr<Conn>> conns_;
    bool running_ = false;
    bool tls_on_ = false;
};

} // namespace bpb::http
