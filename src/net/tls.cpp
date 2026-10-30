#include "net/tls.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace bpb::net {

namespace {
SSL_CTX* g_ctx = nullptr;
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
