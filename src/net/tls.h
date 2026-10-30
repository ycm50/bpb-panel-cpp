#pragma once
#include "net/net.h"

#include <string>

typedef struct ssl_st SSL;

namespace bpb::net {

bool tls_init_server(const std::string& cert_path, const std::string& key_path, std::string& error);
bool tls_enabled();

// Creates a server-side SSL object for the given socket (handshake not performed yet).
SSL* tls_new_server(net::socket_t fd, std::string& error);
void tls_free(SSL* ssl);

enum class IoResult { Ok, WouldBlock, Closed, Error };

// Reads/writes through TLS or plain socket. len > 0 on Ok.
int tls_read(SSL* ssl, net::socket_t fd, char* buf, int len, IoResult& result);
int tls_write(SSL* ssl, net::socket_t fd, const char* buf, int len, IoResult& result);
int tls_pending(SSL* ssl);
bool tls_wants_write(SSL* ssl);

} // namespace bpb::net
