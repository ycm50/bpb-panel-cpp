#include "net/tls.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstring>

namespace bpb::net {

namespace {
// Legacy process-wide context, kept only for the single-listener entry points
// (tls_init_server / tls_new_server without a TlsContext). The two-listener
// setup uses TlsContext instead.
SSL_CTX* g_ctx = nullptr;
}

TlsContext::~TlsContext() {
    if (ctx_) SSL_CTX_free(ctx_);
    ctx_ = nullptr;
}

bool TlsContext::init(const std::string& cert_path, const std::string& key_path,
                      std::string& error) {
    if (cert_path.empty() || key_path.empty()) {
        error = "certificate path is empty";
        return false;
    }
    SSL_CTX* fresh = SSL_CTX_new(TLS_server_method());
    if (!fresh) {
        error = "SSL_CTX_new failed";
        return false;
    }
    SSL_CTX_set_min_proto_version(fresh, TLS1_2_VERSION);
    SSL_CTX_set_options(fresh, SSL_OP_NO_COMPRESSION);
    if (SSL_CTX_use_certificate_chain_file(fresh, cert_path.c_str()) != 1) {
        error = "cannot load certificate: " + cert_path;
        SSL_CTX_free(fresh);
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(fresh, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        error = "cannot load private key: " + key_path;
        SSL_CTX_free(fresh);
        return false;
    }
    if (SSL_CTX_check_private_key(fresh) != 1) {
        error = "certificate and private key do not match";
        SSL_CTX_free(fresh);
        return false;
    }
    // ALPN: advertise HTTP/1.1 only.
    //
    // This listener multiplexes plain HTTP (panel) and TLS (proxy inbounds) on
    // one port, but its application layer is an HTTP/1.1 server. Negotiating
    // h2 here made browsers and curl agree to HTTP/2 and then hand them an
    // HTTP/1.1 response, which they parse as garbage: the connection hangs and
    // every second request over a fresh socket times out. Anything that offers
    // h2 is therefore told http/1.1 instead.
    //
    // gRPC does NOT rely on ALPN: the h2 owner takes the connection over from
    // the HTTP/2 connection preface ("PRI * HTTP/2.0") in Server::process(),
    // which it can do regardless of what ALPN settled on.
    SSL_CTX_set_alpn_select_cb(
        fresh,
        [](SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
           unsigned int inlen, void*) -> int {
            static const unsigned char h1[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
            // Only answer when the client actually offered it: replying with a
            // protocol the client did not list is a fatal alert.
            for (unsigned int i = 0; i + 1 <= inlen;) {
                const unsigned int len = in[i];
                if (len == 0 || i + 1 + len > inlen) break;
                const unsigned char* p = in + i + 1;
                if (len == 8 && std::memcmp(p, h1, 8) == 0) {
                    *out = h1;
                    *outlen = 8;
                    return SSL_TLSEXT_ERR_OK;
                }
                i += 1 + len;
            }
            return SSL_TLSEXT_ERR_NOACK;
        },
        nullptr);
    SSL_CTX_set_session_cache_mode(fresh, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_mode(fresh, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (ctx_) SSL_CTX_free(ctx_);
    ctx_ = fresh;
    return true;
}

SSL* tls_new_server(TlsContext& ctx, net::socket_t fd, std::string& error) {
    if (!ctx.raw()) {
        error = "tls context not initialised";
        return nullptr;
    }
    SSL* ssl = SSL_new(ctx.raw());
    if (!ssl) {
        error = "SSL_new failed";
        return nullptr;
    }
    SSL_set_fd(ssl, static_cast<int>(fd));
    SSL_set_accept_state(ssl);
    return ssl;
}

bool tls_init_server(const std::string& cert_path, const std::string& key_path, std::string& error) {
    if (cert_path.empty() || key_path.empty()) return false;
    g_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ctx) {
        error = "SSL_CTX_new failed";
        return false;
    }
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_ctx, SSL_OP_NO_COMPRESSION);
    if (SSL_CTX_use_certificate_chain_file(g_ctx, cert_path.c_str()) != 1) {
        error = "cannot load certificate: " + cert_path;
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(g_ctx, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        error = "cannot load private key: " + key_path;
        return false;
    }
    if (SSL_CTX_check_private_key(g_ctx) != 1) {
        error = "certificate and private key do not match";
        return false;
    }
    SSL_CTX_set_session_cache_mode(g_ctx, SSL_SESS_CACHE_SERVER);
    // The server side is non-blocking. Without partial-write mode SSL_write()
    // buffers a whole record internally and reports WANT_WRITE having consumed
    // nothing, so flushing a large response stalls until the peer's socket
    // happens to become writable again. Enabling partial writes lets it return
    // the bytes it actually managed to encode, which is what our flush() loop
    // expects (it erases exactly n bytes and retries the remainder).
    SSL_CTX_set_mode(g_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return true;
}

bool tls_enabled() { return g_ctx != nullptr; }

SSL* tls_new_server(net::socket_t fd, std::string& error) {
    if (!g_ctx) {
        error = "tls not initialised";
        return nullptr;
    }
    SSL* ssl = SSL_new(g_ctx);
    if (!ssl) {
        error = "SSL_new failed";
        return nullptr;
    }
    SSL_set_fd(ssl, static_cast<int>(fd));
    SSL_set_accept_state(ssl);
    return ssl;
}

void tls_free(SSL* ssl) {
    if (!ssl) return;
    SSL_free(ssl);
}

int tls_read(SSL* ssl, net::socket_t fd, char* buf, int len, IoResult& result) {
    if (!ssl) {
        int n = static_cast<int>(::recv(fd, buf, static_cast<int>(len), 0));
        if (n > 0) {
            result = IoResult::Ok;
            return n;
        }
        if (n == 0) {
            result = IoResult::Closed;
            return 0;
        }
        result = net::would_block(net::last_error()) ? IoResult::WouldBlock : IoResult::Error;
        return -1;
    }
    int n = SSL_read(ssl, buf, len);
    if (n > 0) {
        result = IoResult::Ok;
        return n;
    }
    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        result = IoResult::WouldBlock;
        return -1;
    }
    if (err == SSL_ERROR_ZERO_RETURN) {
        result = IoResult::Closed;
        return 0;
    }
    result = IoResult::Error;
    return -1;
}

int tls_write(SSL* ssl, net::socket_t fd, const char* buf, int len, IoResult& result) {
    if (!ssl) {
        int n = static_cast<int>(::send(fd, buf, static_cast<int>(len), 0));
        if (n > 0) {
            result = IoResult::Ok;
            return n;
        }
        result = net::would_block(net::last_error()) ? IoResult::WouldBlock : IoResult::Error;
        return -1;
    }
    int n = SSL_write(ssl, buf, len);
    if (n > 0) {
        result = IoResult::Ok;
        return n;
    }
    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        result = IoResult::WouldBlock;
        return -1;
    }
    result = IoResult::Error;
    return -1;
}

int tls_pending(SSL* ssl) { return ssl ? SSL_pending(ssl) : 0; }

bool tls_wants_write(SSL* ssl) { return ssl && SSL_want_write(ssl); }

} // namespace bpb::net
