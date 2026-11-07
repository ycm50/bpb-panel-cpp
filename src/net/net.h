#pragma once
#include <string>
#include <cstdint>
#include <cstddef>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#endif

namespace bpb::net {

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalid = INVALID_SOCKET;
#else
using socket_t = int;
constexpr socket_t kInvalid = -1;
#endif

struct PollFd {
    socket_t fd;
    short events;
    short revents;
};

#ifdef _WIN32
constexpr short kRead = POLLRDNORM;
constexpr short kWrite = POLLWRNORM;
constexpr short kError = POLLERR;
#else
constexpr short kRead = POLLIN;
constexpr short kWrite = POLLOUT;
constexpr short kError = POLLERR;
#endif

// The peer is gone (or the fd is bogus). These are NOT covered by kError: a
// socket the peer closed reports POLLHUP, and a socket that was closed under us
// reports POLLNVAL. Leaving such an fd in the poll set makes poll() return
// immediately for ever, which is how a bare connect()+close() from a port
// scanner used to pin a whole core.
#ifdef _WIN32
constexpr short kHangup = POLLHUP;
constexpr short kInvalidFd = POLLNVAL;
#else
constexpr short kHangup = POLLHUP;
constexpr short kInvalidFd = POLLNVAL;
#endif

bool init();
void shutdown();
bool set_nonblocking(socket_t fd);
bool set_nodelay(socket_t fd);
bool set_reuseaddr(socket_t fd);
void close(socket_t fd);
int last_error();
std::string error_string(int code);
int poll_fds(PollFd* fds, std::size_t count, int timeout_ms);
bool would_block(int code);

} // namespace bpb::net
