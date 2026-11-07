#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace bpb::tunnel {

// A bidirectional byte pipe to the local origin. Unlike LocalOrigin::request()
// (which buffers a whole response), this exposes a live TCP stream so that
// long-lived protocols such as VLESS over WebSocket can be relayed.
class OriginStream {
public:
    OriginStream() = default;
    ~OriginStream() { close(); }
    OriginStream(const OriginStream&) = delete;
    OriginStream& operator=(const OriginStream&) = delete;

    // Starts a request without waiting for anything: the DNS lookup and the
    // TCP connect happen here (both bounded by the resolver), but the request
    // head is only handed to the socket once the connect completes in step().
    //
    // This must never block on the origin's *response*. The relay calls it from
    // inside an HTTP/2 callback, and the request body of a POST only reaches
    // the origin after that callback returns; waiting for the response head
    // here deadlocks every request that carries a body (the origin waits for
    // the body, we wait for the head, and the edge's PING/WINDOW_UPDATE frames
    // go unread the whole time).
    bool begin(const std::string& host, std::uint16_t port, const std::string& method,
               const std::string& path,
               const std::vector<std::pair<std::string, std::string>>& headers,
               int timeoutMs, std::string& error);

    // Advances the connection/response-head state machine without blocking.
    //   Pending  -- still connecting or waiting for the response head
    //   Ready    -- the response head arrived; responseHead() is valid and the
    //               stream is a raw duplex pipe
    //   Failed   -- the origin is unreachable or timed out; errorText() says why
    enum class Step { Pending, Ready, Failed };
    Step step();

    const std::string& responseHead() const { return responseHead_; }
    const std::string& errorText() const { return error_; }
    std::int64_t ageMs() const;

    // True while the socket is still connecting or the head is incomplete.
    bool pending() const { return state_ == Step::Pending; }

    // True once the whole request head has been handed to the socket. The relay
    // must not half-close the origin before this, or the origin sees a truncated
    // request and drops the connection instead of answering.
    bool requestSent() const {
        return fd_ >= 0 && requestHead_.size() > 0 && headSent_ >= requestHead_.size();
    }

    // Queues bytes for the origin. Never blocks: anything the socket will not
    // take right now is buffered and pushed by flush() on later iterations.
    // cloudflared achieves the same guarantee with one goroutine per direction
    // (stream.Pipe); we cannot spawn a thread per stream, so the equivalent is
    // a non-blocking socket plus this queue. A blocking write here would stall
    // the read direction and deadlock any full-duplex protocol.
    bool write(const void* data, std::size_t len);

    // Pushes as much buffered output as the socket accepts without blocking.
    // Returns false only on a hard socket error.
    bool flush();

    // True when buffered output is still waiting for the socket to drain.
    bool hasPendingOutput() const { return pendingOut_.size() > pendingOutOff_; }
    std::size_t pendingOutputBytes() const { return pendingOut_.size() - pendingOutOff_; }

    // Reads whatever is available, blocking up to timeoutMs. Returns:
    //   >0  bytes read into buf
    //    0  timeout (no data)
    //   -1  peer closed / error
    int readSome(void* buf, std::size_t cap, int timeoutMs);

    int fd() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
    void close();

private:
    int fd_ = -1;
    std::vector<std::uint8_t> pending_;  // bytes read past the response head
    std::size_t pendingOff_ = 0;

    std::vector<std::uint8_t> pendingOut_;  // bytes the origin has not accepted yet
    std::size_t pendingOutOff_ = 0;

    // Connection setup state, advanced by step().
    Step state_ = Step::Pending;
    bool connecting_ = false;      // connect() returned EINPROGRESS
    std::string requestHead_;      // built by begin(), sent once connected
    std::size_t headSent_ = 0;     // bytes of requestHead_ already queued
    std::string headBuf_;          // partial response head accumulation
    std::string responseHead_;
    std::string error_;
    std::int64_t startedAt_ = 0;   // steady_clock ms, for the head timeout
    int timeoutMs_ = 15000;
};

// Minimal HTTP/1.1 client used for ordinary request/response exchanges.
class LocalOrigin {
public:
    struct Response {
        int status = 0;
        std::string reason;
        std::vector<std::pair<std::string, std::string>> headers;
        std::vector<std::uint8_t> body;
    };

    static bool request(const std::string& host, std::uint16_t port, const std::string& method,
                        const std::string& path,
                        const std::vector<std::pair<std::string, std::string>>& headers,
                        const std::vector<std::uint8_t>& body, bool keepAlive, Response& out,
                        std::string& error);
};

} // namespace bpb::tunnel
