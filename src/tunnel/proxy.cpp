#include "tunnel/proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace bpb::tunnel {

namespace {

std::int64_t mono_ms() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

// Linux accepts SOCK_NONBLOCK inside socket(); older libcs do not.
inline int sock_type_flag() {
#ifdef SOCK_NONBLOCK
    return SOCK_NONBLOCK;
#else
    return 0;
#endif
}

int dial(const std::string& host, std::uint16_t port, std::string& error, int timeoutMs) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string ps = std::to_string(port);
    if (getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || !res) {
        error = "resolve failed: " + host;
        return -1;
    }
    int fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        if (::connect(s, p->ai_addr, p->ai_addrlen) == 0) { fd = s; break; }
        ::close(s);
    }
    freeaddrinfo(res);
    if (fd < 0) {
        error = "connect failed " + host + ":" + ps;
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (timeoutMs > 0) {
        struct timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    // Non-blocking from here on: both directions are driven by one poll loop,
    // so neither side may ever block inside a send(). Callers use flush() to
    // push whatever the socket would not take immediately.
    int fl = ::fcntl(fd, F_GETFL, 0);
    if (fl >= 0) ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

bool send_all(int fd, const void* data, std::size_t len) {
    const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) return false;
        off += static_cast<std::size_t>(n);
    }
    return true;
}

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    std::size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    std::size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

} // namespace

// --- OriginStream ----------------------------------------------------------

bool OriginStream::begin(const std::string& host, std::uint16_t port, const std::string& method,
                         const std::string& path,
                         const std::vector<std::pair<std::string, std::string>>& headers,
                         int timeoutMs, std::string& error) {
    timeoutMs_ = timeoutMs > 0 ? timeoutMs : 15000;
    startedAt_ = mono_ms();
    state_ = Step::Pending;
    error_.clear();

    std::ostringstream req;
    req << method << ' ' << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    bool haveHost = false;
    for (auto& kv : headers) {
        const std::string ln = lower(kv.first);
        if (ln.empty() || ln[0] == ':') continue;
        if (ln == "host") haveHost = true;
        req << kv.first << ": " << kv.second << "\r\n";
    }
    if (!haveHost) req << "Host: " << host << ":" << port << "\r\n";
    req << "\r\n";
    requestHead_ = req.str();
    headSent_ = 0;
    if (::getenv("BPB_TUNNEL_TRACE")) {
        std::fprintf(stderr, "[origin] head -> %s:%u\n%.600s---\n", host.c_str(),
                     static_cast<unsigned>(port), requestHead_.c_str());
        std::fflush(stderr);
    }

    // Resolve + create the socket. The connect itself is non-blocking so a
    // blackholed origin cannot stall the relay; step() completes it.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string ps = std::to_string(port);
    if (getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || !res) {
        error_ = "resolve failed: " + host;
        error = error_;
        state_ = Step::Failed;
        return false;
    }
    int fd = -1;
    bool inprogress = false;
    for (addrinfo* p = res; p; p = p->ai_next) {
        int s = ::socket(p->ai_family, p->ai_socktype | sock_type_flag(), p->ai_protocol);
        if (s < 0) continue;
        const int rc = ::connect(s, p->ai_addr, p->ai_addrlen);
        if (rc == 0) { fd = s; inprogress = false; break; }
        if (errno == EINPROGRESS) { fd = s; inprogress = true; break; }
        ::close(s);
    }
    freeaddrinfo(res);
    if (fd < 0) {
        error_ = "connect failed " + host + ":" + ps;
        error = error_;
        state_ = Step::Failed;
        return false;
    }
    fd_ = fd;
    connecting_ = inprogress;
    int one = 1;
    setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // When the connect completed synchronously (the common case for a loopback
    // origin), flush the request head immediately. Otherwise the caller's first
    // write() lands while headSent_ < requestHead_.size(), our flush() parks it,
    // and nobody ever advances the state machine -- the origin never receives
    // the request at all. That is the "stalled at ~3 KB, edge resets at 15s"
    // signature.
    if (!connecting_) {
        if (!flush()) {
            error_ = "send head failed";
            error = error_;
            state_ = Step::Failed;
            close();
            return false;
        }
    }
    return true;
}

int64_t OriginStream::ageMs() const { return mono_ms() - startedAt_; }

// One non-blocking turn of the connect -> send head -> read head pipeline.
OriginStream::Step OriginStream::step() {
    if (state_ != Step::Pending) return state_;
    if (fd_ < 0) {
        state_ = Step::Failed;
        if (error_.empty()) error_ = "socket closed";
        return state_;
    }
    const auto fail = [&](const std::string& why) {
        error_ = why;
        state_ = Step::Failed;
        return state_;
    };

    if (connecting_) {
        pollfd pfd{fd_, POLLOUT, 0};
        const int pr = ::poll(&pfd, 1, 0);
        if (pr == 0) {
            if (ageMs() > timeoutMs_) return fail("connect timeout");
            return Step::Pending;
        }
        if (pr < 0) return fail("poll failed during connect");
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0)
            return fail("connect failed");
        connecting_ = false;
    }

    // Hand the request head to the socket, as far as it will take it.
    while (headSent_ < requestHead_.size()) {
        if (pendingOut_.size() - pendingOutOff_ >= 8u * 1024 * 1024)
            return fail("origin request queue overflow");
        const ssize_t n = ::send(fd_, requestHead_.data() + headSent_,
                                 requestHead_.size() - headSent_, MSG_NOSIGNAL);
        if (n > 0) {
            headSent_ += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
        return fail("send head failed");
    }
    if (headSent_ < requestHead_.size()) {
        if (ageMs() > timeoutMs_) return fail("send head timeout");
        return Step::Pending;
    }
    // Head is out; release anything that was queued behind it (the request
    // body may have arrived while we were still connecting).
    if (hasPendingOutput() && !flush()) return fail("send body failed");

    // Collect the response head.
    char tmp[8192];
    for (;;) {
        const ssize_t n = ::recv(fd_, tmp, sizeof(tmp), 0);
        if (n > 0) {
            headBuf_.append(tmp, static_cast<std::size_t>(n));
            const std::size_t hdrEnd = headBuf_.find("\r\n\r\n");
            if (hdrEnd != std::string::npos) {
                responseHead_ = headBuf_.substr(0, hdrEnd);
                // Preserve any body bytes that arrived with the head.
                pending_.assign(headBuf_.begin() + static_cast<std::ptrdiff_t>(hdrEnd + 4),
                                headBuf_.end());
                pendingOff_ = 0;
                headBuf_.clear();
                state_ = Step::Ready;
                return state_;
            }
            if (headBuf_.size() > 256 * 1024) return fail("response head too large");
            continue;
        }
        if (n == 0) return fail("origin closed before response head");
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
        return fail("recv head failed");
    }
    if (ageMs() > timeoutMs_) return fail("timeout waiting for response head");
    return Step::Pending;
}

bool OriginStream::write(const void* data, std::size_t len) {
    if (fd_ < 0) return false;
    const std::size_t queued = pendingOut_.size() - pendingOutOff_;
    // Keep the queue bounded; past this the peer is simply not reading, and
    // growing without limit would turn a stall into an OOM.
    constexpr std::size_t kMaxQueued = 8u * 1024 * 1024;
    if (queued + len > kMaxQueued) return false;
    const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
    pendingOut_.insert(pendingOut_.end(), p, p + len);
    return flush();
}

bool OriginStream::flush() {
    if (fd_ < 0) return false;
    // The request head is written by step(); queued body bytes must never jump
    // ahead of it. While the head is still incomplete, keep the queue parked
    // and let step() drain it once the head is out.
    if (headSent_ < requestHead_.size()) return true;
    while (pendingOutOff_ < pendingOut_.size()) {
        ssize_t n = ::send(fd_, pendingOut_.data() + pendingOutOff_,
                           pendingOut_.size() - pendingOutOff_, MSG_NOSIGNAL);
        if (n > 0) {
            pendingOutOff_ += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
        return false;  // hard error: the origin is gone
    }
    if (pendingOutOff_ >= pendingOut_.size()) {
        pendingOut_.clear();
        pendingOutOff_ = 0;
    } else if (pendingOutOff_ > 256 * 1024) {
        // Compact occasionally so the front of the buffer does not grow forever.
        pendingOut_.erase(pendingOut_.begin(),
                          pendingOut_.begin() + static_cast<std::ptrdiff_t>(pendingOutOff_));
        pendingOutOff_ = 0;
    }
    return true;
}

int OriginStream::readSome(void* buf, std::size_t cap, int timeoutMs) {
    if (fd_ < 0) return -1;
    // Serve buffered bytes first.
    if (pendingOff_ < pending_.size()) {
        std::size_t avail = pending_.size() - pendingOff_;
        std::size_t n = avail < cap ? avail : cap;
        std::memcpy(buf, pending_.data() + pendingOff_, n);
        pendingOff_ += n;
        if (pendingOff_ >= pending_.size()) { pending_.clear(); pendingOff_ = 0; }
        return static_cast<int>(n);
    }

    pollfd pfd{fd_, POLLIN, 0};
    int pr = ::poll(&pfd, 1, timeoutMs);
    if (pr == 0) return 0;                 // timeout
    if (pr < 0) return -1;
    if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) return -1;
    ssize_t n = ::recv(fd_, buf, cap, 0);
    if (n > 0) return static_cast<int>(n);
    if (n == 0) return -1;                 // peer closed
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    return -1;
}

void OriginStream::close() {
    // Idempotent: the relay closes on reset, on error and on retire, and the
    // shared_ptr destructor may run again afterwards.
    if (fd_ >= 0) {
        // Best effort: hand any still-queued request bytes to the origin before
        // tearing the socket down.
        flush();
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
    if (state_ == Step::Pending) state_ = Step::Failed;
    headBuf_.clear();
    connecting_ = false;
    pending_.clear();
    pendingOff_ = 0;
    pendingOut_.clear();
    pendingOutOff_ = 0;
}

// --- LocalOrigin -----------------------------------------------------------

bool LocalOrigin::request(const std::string& host, std::uint16_t port, const std::string& method,
                          const std::string& path,
                          const std::vector<std::pair<std::string, std::string>>& headers,
                          const std::vector<std::uint8_t>& body, bool keepAlive, Response& out,
                          std::string& error) {
    int fd = dial(host, port, error, 15000);
    if (fd < 0) return false;

    std::ostringstream req;
    req << method << ' ' << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << host << ":" << port << "\r\n";
    bool haveLength = false;
    for (auto& kv : headers) {
        const std::string ln = lower(kv.first);
        if (ln == "host" || ln == "connection" || ln == "transfer-encoding") continue;
        if (ln == "content-length") haveLength = true;
        req << kv.first << ": " << kv.second << "\r\n";
    }
    if (!haveLength) req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: " << (keepAlive ? "keep-alive" : "close") << "\r\n\r\n";

    std::string head = req.str();
    if (!send_all(fd, head.data(), head.size()) ||
        (!body.empty() && !send_all(fd, body.data(), body.size()))) {
        error = "send failed";
        ::close(fd);
        return false;
    }

    std::string buf;
    std::size_t hdrEnd = std::string::npos;
    char tmp[8192];
    while (hdrEnd == std::string::npos) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) { error = "recv failed (headers)"; ::close(fd); return false; }
        buf.append(tmp, static_cast<std::size_t>(n));
        hdrEnd = buf.find("\r\n\r\n");
        if (buf.size() > 1024 * 1024) { error = "headers too large"; ::close(fd); return false; }
    }

    std::string headBlock = buf.substr(0, hdrEnd);
    std::string rest = buf.substr(hdrEnd + 4);

    std::istringstream hs(headBlock);
    std::string statusLine;
    std::getline(hs, statusLine);
    {
        std::istringstream sl(statusLine);
        std::string ver;
        sl >> ver >> out.status;
        std::getline(sl, out.reason);
        out.reason = trim(out.reason);
    }

    std::size_t contentLength = std::string::npos;
    bool chunked = false;
    std::string line;
    while (std::getline(hs, line)) {
        line = trim(line);
        if (line.empty()) continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = trim(line.substr(0, colon));
        std::string value = trim(line.substr(colon + 1));
        out.headers.emplace_back(name, value);
        const std::string ln = lower(name);
        if (ln == "content-length") contentLength = static_cast<std::size_t>(std::stoull(value));
        if (ln == "transfer-encoding" && lower(value).find("chunked") != std::string::npos)
            chunked = true;
    }

    out.body.assign(rest.begin(), rest.end());
    if (contentLength != std::string::npos) {
        while (out.body.size() < contentLength) {
            ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            out.body.insert(out.body.end(), tmp, tmp + n);
        }
        if (out.body.size() > contentLength) out.body.resize(contentLength);
    } else if (chunked) {
        for (;;) {
            std::string s(out.body.begin(), out.body.end());
            if (s.find("\r\n0\r\n") != std::string::npos) break;
            ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            out.body.insert(out.body.end(), tmp, tmp + n);
        }
    } else {
        for (;;) {
            ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            out.body.insert(out.body.end(), tmp, tmp + n);
        }
    }
    ::close(fd);
    return true;
}

} // namespace bpb::tunnel
