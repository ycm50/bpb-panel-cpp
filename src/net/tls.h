#pragma once
#include "net/net.h"

#include <string>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace bpb::net {

// Server-side TLS context. One per listener, not one per process: the panel
// stays plain HTTP while the proxy listener terminates TLS (the Xray rule that
// banned plaintext VLESS to a public address is why a TLS listener exists at
// all), and a single global context made those two mutually exclusive.
class TlsContext {
public:
    TlsContext() = default;
    ~TlsContext();
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    bool init(const std::string& cert_path, const std::string& key_path, std::string& error);
    bool ready() const { return ctx_ != nullptr; }

    // Copies of this context are never shared between threads; the pointer is
    // only read while a connection is being set up on the listener's thread.
    SSL_CTX* raw() const { return ctx_; }

private:
    SSL_CTX* ctx_ = nullptr;
};

bool tls_init_server(const std::string& cert_path, const std::string& key_path, std::string& error);
bool tls_enabled();

// Creates a server-side SSL object for the given socket (handshake not performed yet).
SSL* tls_new_server(net::socket_t fd, std::string& error);
// Same, against an explicit context (one listener per TlsContext).
SSL* tls_new_server(TlsContext& ctx, net::socket_t fd, std::string& error);
void tls_free(SSL* ssl);

enum class IoResult { Ok, WouldBlock, Closed, Error };

// Reads/writes through TLS or plain socket. len > 0 on Ok.
int tls_read(SSL* ssl, net::socket_t fd, char* buf, int len, IoResult& result);
int tls_write(SSL* ssl, net::socket_t fd, const char* buf, int len, IoResult& result);
int tls_pending(SSL* ssl);
bool tls_wants_write(SSL* ssl);

} // namespace bpb::net
