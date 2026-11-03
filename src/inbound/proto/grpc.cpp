#include "inbound/proto/grpc.h"

#include "inbound/inbound.h"
#include "util/log.h"
#include "util/thread.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string_view>
#include <unordered_map>

namespace bpb::proxy::grpc {

namespace {

constexpr std::size_t kGrpcHeader = 5;   // 1 flag byte + 4-byte big-endian length

// Xray writes at most buf.Size (32 KiB) per Send(), which becomes one message.
// The same bound is used on our side, so a single hunk never exceeds what a
// client's default maxReceiveMessageSize (4 MiB) accepts.
constexpr std::size_t kMaxHunk = 32 * 1024;

// A gRPC message longer than this is a broken peer. The bound keeps a nonsense
// length field from turning into an allocation.
constexpr std::uint32_t kMaxMessage = 4 * 1024 * 1024;

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::mutex g_config_mutex;
SessionConfig g_config;

void put_be32(std::string& out, std::uint32_t v) {
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>(v & 0xFF));
}

void put_varint(std::string& out, std::uint64_t v) {
    while (v >= 0x80) {
        out.push_back(static_cast<char>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<char>(v));
}

bool read_varint(const std::uint8_t* p, std::size_t len, std::size_t& pos, std::uint64_t& out) {
    out = 0;
    int shift = 0;
    while (true) {
        if (pos >= len) return false;
        const std::uint8_t b = p[pos++];
        out |= static_cast<std::uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) return true;
        shift += 7;
        if (shift > 63) return false;
    }
}

// A gRPC message body is a protobuf message, not raw bytes:
//
//   message Hunk      { bytes data = 1; }             // Tun
//   message MultiHunk { repeated bytes data = 1; }    // TunMulti
//
// Both encode as one or more "field 1, wire type 2" segments -- 0x0A, a varint
// length, the bytes -- and the payload is their concatenation in order. Anything
// else in the message is skipped by wire type, as protobuf requires.
bool append_hunk(const std::uint8_t* p, std::size_t len, std::string& out) {
    std::size_t pos = 0;
    while (pos < len) {
        std::uint64_t tag = 0;
        if (!read_varint(p, len, pos, tag)) return false;
        const std::uint32_t field = static_cast<std::uint32_t>(tag >> 3);
        const std::uint32_t wire = static_cast<std::uint32_t>(tag & 0x07);
        if (wire == 2) {   // length-delimited: the only one that carries payload
            std::uint64_t n = 0;
            if (!read_varint(p, len, pos, n)) return false;
            if (n > len - pos) return false;
            if (field == 1) {
                out.append(reinterpret_cast<const char*>(p + pos), static_cast<std::size_t>(n));
            }
            pos += static_cast<std::size_t>(n);
        } else if (wire == 0) {   // varint
            std::uint64_t ignored = 0;
            if (!read_varint(p, len, pos, ignored)) return false;
        } else if (wire == 1) {   // fixed64
            if (len - pos < 8) return false;
            pos += 8;
        } else if (wire == 5) {   // fixed32
            if (len - pos < 4) return false;
            pos += 4;
        } else {
            return false;   // groups / invalid wire types never appear here
        }
    }
    return true;
}

// "/vlg/Tun" -> "vlg": the first path segment selects the inbound, the rest is
// the gRPC method name (Tun, or TunMulti with multiMode on).
std::string first_segment(const std::string& path) {
    std::size_t i = 0;
    while (i < path.size() && path[i] == '/') ++i;
    const std::size_t start = i;
    while (i < path.size() && path[i] != '/' && path[i] != '?') ++i;
    return path.substr(start, i - start);
}

// Xray PathEscapes a serviceName that itself contains a slash, so "/a%2Fb/Tun"
// is the escaped form of the service name "a/b". Decoding is attempted only when
// the raw segment matches nothing.
std::string percent_decode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            const auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(in[i + 1]);
            const int lo = hex(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

std::string field(const h2s::Headers& headers, std::string_view name) {
    for (const auto& f : headers) {
        if (f.first == name) return f.second;
    }
    return {};
}


// ---------------------------------------------------------------------------

// One gRPC stream seen as a byte stream. The framing lives here: bytes arrive
// from the HTTP/2 layer in arbitrary slices, are reassembled into gRPC messages,
// the protobuf hunk inside each message is unwrapped, and the bytes are queued
// for the session. Message boundaries carry no meaning above this point -- a
// VLESS header may end in the middle of a message and a message may hold the
// tail of a header plus the first bytes of the payload.
class StreamImpl final : public Stream {
public:
    StreamImpl(std::weak_ptr<h2s::Server> server, std::uint32_t id, std::string path)
        : server_(std::move(server)), id_(id), path_(std::move(path)) {}

    // --- called from the connection thread
    void feed_data(const char* data, std::size_t len);
    void feed_end();
    void feed_reset();

    // --- Stream
    int read(char* buf, int len, int timeout_ms) override;
    bool write(const char* data, std::size_t len) override;
    void close() override;
    const std::string& path() const override { return path_; }

private:
    std::size_t available() const { return buf_.size() - off_; }
    void credit(std::size_t bytes);

    std::weak_ptr<h2s::Server> server_;
    std::uint32_t id_ = 0;
    std::string path_;

    std::mutex mu_;
    std::condition_variable cv_;
    // Unwrapped payload bytes the session has not taken yet.
    std::string buf_;
    std::size_t off_ = 0;
    // The gRPC message being reassembled: a message may be split across DATA
    // frames, and several messages may share one frame.
    std::string msg_;
    std::size_t msg_need_ = 0;   // total size once the 5-byte header is known
    bool remote_end_ = false;
    bool dead_ = false;
    bool closed_ = false;
};

void StreamImpl::feed_data(const char* data, std::size_t len) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (dead_) return;
        msg_.append(data, len);
        std::size_t done = 0;
        while (true) {
            if (msg_need_ == 0) {
                if (msg_.size() - done < kGrpcHeader) break;
                const auto* p = reinterpret_cast<const unsigned char*>(msg_.data() + done);
                if (p[0] != 0) {
                    // A compressed message needs a decompressor this transport
                    // deliberately does not carry (xray never sets the flag).
                    // Failing the stream beats feeding garbage upstream.
                    if (bpb::log::enabled(bpb::log::kDebug))
                        std::fprintf(stderr, "[grpc] compressed message on stream %u\n", id_);
                    dead_ = true;
                    break;
                }
                const std::uint32_t n = (static_cast<std::uint32_t>(p[1]) << 24) |
                                        (static_cast<std::uint32_t>(p[2]) << 16) |
                                        (static_cast<std::uint32_t>(p[3]) << 8) |
                                        static_cast<std::uint32_t>(p[4]);
                if (n > kMaxMessage) {
                    dead_ = true;
                    break;
                }
                msg_need_ = kGrpcHeader + n;
            }
            if (msg_.size() - done < msg_need_) break;
            if (!append_hunk(reinterpret_cast<const std::uint8_t*>(msg_.data() + done + kGrpcHeader),
                             msg_need_ - kGrpcHeader, buf_)) {
                if (bpb::log::enabled(bpb::log::kDebug))
                    std::fprintf(stderr, "[grpc] malformed hunk on stream %u\n", id_);
                dead_ = true;
                break;
            }
            done += msg_need_;
            msg_need_ = 0;
        }
        if (done) msg_.erase(0, done);
    }
    cv_.notify_all();
}

void StreamImpl::feed_end() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        remote_end_ = true;
    }
    cv_.notify_all();
}

void StreamImpl::feed_reset() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        dead_ = true;
    }
    cv_.notify_all();
}

void StreamImpl::credit(std::size_t bytes) {
    if (bytes == 0) return;
    if (auto server = server_.lock()) server->consume(id_, bytes);
}

int StreamImpl::read(char* buf, int len, int timeout_ms) {
    if (len <= 0) return 0;
    const std::int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    std::size_t taken = 0;
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (available() > 0) {
                taken = std::min<std::size_t>(available(), static_cast<std::size_t>(len));
                std::memcpy(buf, buf_.data() + off_, taken);
                off_ += taken;
                if (off_ == buf_.size()) {
                    buf_.clear();
                    off_ = 0;
                }
                break;
            }
            if (dead_ || remote_end_) return -1;
        }
        // The connection behind the stream can die without any frame arriving
        // (the peer vanished); nothing would wake this thread, so the connection
        // is checked on every slice instead of waiting for a notification that
        // never comes.
        if (auto server = server_.lock(); !server || !server->alive()) {
            std::lock_guard<std::mutex> lk(mu_);
            dead_ = true;
            if (available() > 0) continue;
            return -1;
        }
        if (now_ms() >= deadline) return 0;
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, std::chrono::milliseconds(50),
                     [&] { return available() > 0 || dead_ || remote_end_; });
    }
    credit(taken);
    cv_.notify_all();   // wakes the HTTP/2 buffering ceiling in h2s
    return static_cast<int>(taken);
}

bool StreamImpl::write(const char* data, std::size_t len) {
    auto server = server_.lock();
    if (!server) return false;
    if (len == 0) return true;
    std::size_t off = 0;
    while (off < len) {
        const std::size_t chunk = std::min<std::size_t>(len - off, kMaxHunk);
        // message = 5-byte gRPC header + Hunk{data} = 0x0A + varint + bytes.
        // The length field is patched at the end, so the payload is built once.
        std::string message;
        message.reserve(kGrpcHeader + 5 + chunk);
        message.append(kGrpcHeader, '\0');
        message.push_back(static_cast<char>(0x0A));   // field 1, wire type 2
        put_varint(message, chunk);
        message.append(data + off, chunk);
        const std::uint32_t body = static_cast<std::uint32_t>(message.size() - kGrpcHeader);
        message[0] = '\0';   // not compressed
        message[1] = static_cast<char>((body >> 24) & 0xFF);
        message[2] = static_cast<char>((body >> 16) & 0xFF);
        message[3] = static_cast<char>((body >> 8) & 0xFF);
        message[4] = static_cast<char>(body & 0xFF);
        if (!server->write_data(id_, message.data(), message.size())) return false;
        off += chunk;
    }
    return true;
}

void StreamImpl::close() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return;
        closed_ = true;
    }
    auto server = server_.lock();
    if (!server) return;
    // Trailers: 200 is already on the wire, so this is a second header block
    // with END_STREAM carrying the gRPC status. A client that gets RST_STREAM or
    // a bare TCP close instead reports the completed download as a failure
    // ("server closed the stream without sending trailers").
    h2s::Headers trailers;
    trailers.emplace_back("grpc-status", "0");
    server->write_headers(id_, trailers, true);
    server->close_stream(id_);
}


// ---------------------------------------------------------------------------

// Per-connection state. Held by the handler lambdas the HTTP/2 layer calls; it
// keeps only a weak reference to that layer, so the two do not own each other.
class Connection final : public std::enable_shared_from_this<Connection> {
public:
    explicit Connection(SessionConfig config) : config_(std::move(config)) {}

    void attach(const std::shared_ptr<h2s::Server>& server) { server_ = server; }

    h2s::Handlers handlers() {
        h2s::Handlers h;
        auto self = shared_from_this();
        h.on_headers = [self](std::uint32_t sid, const h2s::Headers& headers) {
            self->on_headers(sid, headers);
        };
        h.on_data = [self](std::uint32_t sid, const char* data, std::size_t len) {
            if (auto s = self->find(sid)) s->feed_data(data, len);
        };
        h.on_end_stream = [self](std::uint32_t sid) {
            if (auto s = self->find(sid)) s->feed_end();
        };
        h.on_reset_stream = [self](std::uint32_t sid) {
            if (auto s = self->find(sid)) s->feed_reset();
            self->streams_.erase(sid);
        };
        return h;
    }

private:
    std::shared_ptr<StreamImpl> find(std::uint32_t sid) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) return nullptr;
        return it->second.lock();
    }

    // Streams the session already released must not keep their buffers alive;
    // entries are only touched on the connection thread.
    void prune() {
        for (auto it = streams_.begin(); it != streams_.end();) {
            if (it->second.expired()) it = streams_.erase(it);
            else ++it;
        }
    }

    // Trailers-only response, the way a grpc-go server answers a method it does
    // not have: ":status 200" plus "grpc-status: 12" (UNIMPLEMENTED) in one
    // header block with END_STREAM.
    void refuse(std::uint32_t sid, const char* status, const char* grpc_status,
                const char* content_type) {
        auto server = server_.lock();
        if (!server) return;
        h2s::Headers headers;
        headers.emplace_back(":status", status);
        headers.emplace_back("content-type", content_type);
        headers.emplace_back("grpc-status", grpc_status);
        server->write_headers(sid, headers, true);
        server->close_stream(sid);
    }

    void start(std::uint32_t sid, const std::string& path, StreamHandler handler) {
        auto server = server_.lock();
        if (!server) return;
        auto stream = std::make_shared<StreamImpl>(server_, sid, path);
        // Initial metadata first: a gRPC client blocks its first read until the
        // server's response headers arrive, and it rejects the stream outright if
        // content-type says it is not gRPC.
        h2s::Headers response;
        response.emplace_back(":status", "200");
        response.emplace_back("content-type", "application/grpc");
        if (!server->write_headers(sid, response, false)) return;
        streams_[sid] = stream;
        const SessionConfig config = config_;
        // The session runs on its own thread: this one must get back to reading
        // frames, or the peer's window stays shut and nothing moves.
        bpb::util::spawn_detached([stream, handler, config] {
            handler(stream, config);
            stream->close();
            // Hand this session's pages back instead of parking them in a glibc
            // arena: sessions in a row otherwise leave the process several MB
            // above its cold-start footprint.
            bpb::util::release_free_memory();
        });
    }

    void on_headers(std::uint32_t sid, const h2s::Headers& headers) {
        prune();
        if (bpb::log::enabled(bpb::log::kTrace)) {
            std::fprintf(stderr, "[grpc] headers stream=%u:", sid);
            for (const auto& f : headers) std::fprintf(stderr, " %s=%s", f.first.c_str(), f.second.c_str());
            std::fputc('\n', stderr);
        }
        const std::string path = field(headers, ":path");
        if (path.empty()) {
            refuse(sid, "400", "13", "text/plain");
            return;
        }
        const std::string content_type = field(headers, "content-type");
        if (!content_type.empty() && content_type.rfind("application/grpc", 0) != 0) {
            // Not a gRPC request: answering is friendlier than a silent RST, and
            // a browser poking the port sees why nothing happens.
            refuse(sid, "415", "13", "text/plain");
            return;
        }
        const std::string segment = first_segment(path);
        const inbound::Inbound* in = inbound::by_path(segment, config_);
        if (!in && segment != percent_decode(segment)) {
            in = inbound::by_path(percent_decode(segment), config_);
        }
        if (!in) {
            // Same answer grpc-go gives for an unknown method.
            refuse(sid, "200", "12", "application/grpc");
            return;
        }
#ifdef BPB_HAVE_VLESS_GRPC
        if (std::string_view(in->id) == "vless-grpc") {
            if (bpb::log::enabled(bpb::log::kTrace))
                std::fprintf(stderr, "[grpc] stream %u path=%s\n", sid, path.c_str());
            start(sid, path, &::bpb::proxy::grpc::vless_grpc_stream);
            return;
        }
#endif
        refuse(sid, "200", "12", "application/grpc");
    }

    std::weak_ptr<h2s::Server> server_;
    SessionConfig config_;
    std::unordered_map<std::uint32_t, std::weak_ptr<StreamImpl>> streams_;
};

} // namespace

void set_config(SessionConfig config) {
    std::lock_guard<std::mutex> lk(g_config_mutex);
    g_config = std::move(config);
}

h2s::Settings transport_settings() {
    h2s::Settings s;
    // Xray dials one ClientConn per outbound and multiplexes every session onto
    // it; grpc-go queues (it does not fail) once the peer's stream quota is used
    // up, so a low number here shows up as "the second user never connects".
    s.max_concurrent_streams = 256;
    // 256 KiB per stream and 2 MiB per connection, reopened in batches as the
    // session consumes. The protocol default of 64 KiB per window caps a
    // connection at one window per RTT -- on a 200 ms path that is 300 KiB/s.
    s.stream_window = 256 * 1024;
    s.connection_window = 2 * 1024 * 1024;
    s.stream_credit_batch = 64 * 1024;
    s.connection_credit_batch = 1024 * 1024;
    s.max_buffered = 4 * 1024 * 1024;
    // Xray's gRPC client sends a keepalive PING only when idle_timeout is set,
    // and its BDP probe PINGs while a transfer runs; a really idle connection is
    // therefore either dead or finished with.
    s.idle_ms = 60000;
    return s;
}

bool pre_takeover(net::socket_t fd, SSL* ssl, const std::string& buffered,
                  const SessionConfig& config) {
    static const std::string kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (buffered.size() < kPreface.size() || buffered.compare(0, kPreface.size(), kPreface) != 0) {
        // Not HTTP/2: leave the connection to the HTTP server, which is also what
        // happens when this transport was not asked for.
        return false;
    }
    auto conn = std::make_shared<Connection>(config);
    auto server = h2s::create(fd, ssl, buffered, conn->handlers(), transport_settings());
    // The handlers above captured conn; conn keeps the connection only weakly,
    // so there is no ownership cycle: the thread below owns the server.
    conn->attach(server);
    bpb::util::spawn_detached([server] { server->run(); });
    return true;
}

bool pre_takeover(net::socket_t fd, SSL* ssl, const std::string& buffered) {
    SessionConfig config;
    {
        std::lock_guard<std::mutex> lk(g_config_mutex);
        config = g_config;
    }
    return pre_takeover(fd, ssl, buffered, config);
}

} // namespace bpb::proxy::grpc
