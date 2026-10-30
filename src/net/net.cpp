#include "net/net.h"

namespace bpb::net {

bool init() {
#ifdef _WIN32
    WSADATA wsa{};
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}

void shutdown() {
#ifdef _WIN32
    WSACleanup();
#endif
}

bool set_nonblocking(socket_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool set_nodelay(socket_t fd) {
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&one), sizeof(one)) == 0;
}

bool set_reuseaddr(socket_t fd) {
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<const char*>(&one), sizeof(one)) == 0;
}

void close(socket_t fd) {
#ifdef _WIN32
    closesocket(fd);
#else
    ::close(fd);
#endif
}

int last_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string error_string(int code) {
#ifdef _WIN32
    char buf[256] = {0};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   static_cast<DWORD>(code), 0, buf, sizeof(buf) - 1, nullptr);
    std::string s(buf);
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s.empty() ? ("wsa error " + std::to_string(code)) : s;
#else
    return std::string(strerror(code));
#endif
}

int poll_fds(PollFd* fds, std::size_t count, int timeout_ms) {
#ifdef _WIN32
    return WSAPoll(reinterpret_cast<WSAPOLLFD*>(fds), static_cast<ULONG>(count), timeout_ms);
#else
    return ::poll(reinterpret_cast<struct pollfd*>(fds), static_cast<nfds_t>(count), timeout_ms);
#endif
}

bool would_block(int code) {
#ifdef _WIN32
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS;
#else
    return code == EAGAIN || code == EWOULDBLOCK || code == EINPROGRESS;
#endif
}

} // namespace bpb::net
