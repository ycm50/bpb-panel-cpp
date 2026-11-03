#include "inbound/proto/xhttp.h"

#include "net/tls.h"
#include "util/log.h"
#include "util/thread.h"
#include "util/util.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <openssl/ssl.h>

#ifdef _WIN32
#include <mstcpip.h>
#else
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

namespace bpb::proxy::xhttp {

namespace {

// One slice per direction: idle sessions pay two wake-ups per 100 ms instead of
// a spin loop, and a finished session notices its stop flag within a slice.
constexpr int kWaitSliceMs = 100;
// Per-session buffers. The relay hands the same 16 KB back and forth instead of
// allocating per block: 200 live sessions would otherwise churn megabytes.
constexpr std::size_t kChunk = 16384;
// Uplink backlog before the POST reader is told to wait (backpressure towards
// the client instead of unbounded growth when the origin is slow).
constexpr std::size_t kUpQueueCap = 4 * 1024 * 1024;
// Downlink backlog before the download direction blocks waiting for the writer.
constexpr std::size_t kDownQueueCap = 1024 * 1024;
// How far the client may run ahead of a missing sequence number before we keep
// the packets instead of dropping them (it posts concurrently, so a small
// reorder window is normal).
constexpr std::size_t kReorderCap = 256;
constexpr std::size_t kReorderBytes = 4 * 1024 * 1024;
// A sequence hole that never fills (that POST was lost on a connection the
// client still pooled) would stall the stream for ever; after this long the
// queue skips to the oldest packet it does have.
constexpr std::int64_t kGapMs = 10000;
// No byte in either direction for this long: the session is dead weight.
constexpr std::int64_t kIdleMs = 60000;
// Sessions with no GET, or abandoned between sessions, would otherwise live as
// long as the process; 512 covers a busy relay and bounds the memory.
constexpr std::size_t kMaxSessions = 512;
constexpr std::size_t kMaxHeadBytes = 32 * 1024;
constexpr std::size_t kMaxPostBytes = 16 * 1024 * 1024;
// The client pools its upload connections (uploadRawPool) and hands the next
// packet to whatever connection it wrote last, even when that packet belongs to
// a *new* session. Such a connection must stay open long enough to be reused --
// xray's own conn idle timeout is 5 minutes -- and must never be closed while
// the pool still points at it: the client would write a whole POST into a dead
// socket and lose the session's first packet.
constexpr std::int64_t kUplinkIdleMs = 120000;

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// send() that keeps going through short writes and WouldBlock. The downlink is
// chunked, so a half written chunk would corrupt the framing and the client
// would drop the stream even though the payload was fine.
bool send_all(SSL* ssl, net::socket_t fd, const char* data, std::size_t len) {
    std::size_t sent = 0;
    int stalls = 0;
    while (sent < len) {
        net::IoResult result = net::IoResult::Error;
        int n = net::tls_write(ssl, fd, data + sent, static_cast<int>(len - sent), result);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (result == net::IoResult::WouldBlock) {
            // A slow peer is not a dead peer: the client's window stays shut
            // while it drains its own buffers. Only a minute of zero progress
            // is treated as a dead connection.
            net::PollFd pfd{fd, net::kWrite, 0};
            if (net::poll_fds(&pfd, 1, 500) <= 0) {
                if (++stalls > 120) return false;
                continue;
            }
            stalls = 0;
            continue;
        }
        return false;
    }
    return true;
}

// Dead peers are invisible to a relay: a middlebox can vanish without a FIN and
// the session then waits for bytes that never come. TCP keepalive makes the
// kernel notice instead of leaving a thread parked for the uptime.
void enable_keepalive(net::socket_t fd) {
    if (fd == net::kInvalid) return;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef _WIN32
    tcp_keepalive ka{1, 60000, 15000};
    DWORD bytes = 0;
    WSAIoctl(fd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes, nullptr, nullptr);
#else
    int idle = 60;
    int intvl = 15;
    int cnt = 4;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

// Wakes whatever blocks on this socket without closing it: the writer owns the
// descriptor and is the only thread allowed to close it.
void shutdown_both(net::socket_t fd) {
    if (fd == net::kInvalid) return;
#ifdef _WIN32
    ::shutdown(fd, SD_BOTH);
#else
    ::shutdown(fd, SHUT_RDWR);
#endif
}

// Session ids are opaque to us: the client generates a uuid (or a random string
// from its own alphabet). Anything outside this set is not an XHTTP session and
// must fall through to the panel instead of being swallowed.
bool valid_sid(const std::string& sid) {
    if (sid.empty() || sid.size() > 128) return false;
    for (char c : sid) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

// "/securepath/vlx/<sid>"            -> sid, no seq  (downlink)
// "/securepath/vlx/<sid>/<seq>"      -> sid, seq     (uplink)
bool split_target(const std::string& path, const std::string& prefix, std::string& sid,
                  std::string& seq, bool& has_seq) {
    has_seq = false;
    sid.clear();
    seq.clear();
    if (prefix.empty() || path.size() <= prefix.size() + 1) return false;
    if (path.compare(0, prefix.size(), prefix) != 0) return false;
    if (path[prefix.size()] != '/') return false;

    std::string rest = path.substr(prefix.size() + 1);
    const std::size_t slash = rest.find('/');
    if (slash == std::string::npos) {
        if (!valid_sid(rest)) return false;
        sid = rest;
        return true;
    }
    sid = rest.substr(0, slash);
    if (!valid_sid(sid)) return false;
    std::string tail = rest.substr(slash + 1);
    const std::size_t slash2 = tail.find('/');
    if (slash2 != std::string::npos) tail = tail.substr(0, slash2);
    if (tail.empty()) return true;
    for (char c : tail) {
        if (c < '0' || c > '9') return true;   // not a sequence: uplink without one
    }
    seq = tail;
    has_seq = true;
    return true;
}

// Where the transport is mounted. It can be handed over as the full path
// ("/securepath/vlx") or as the protocol segment alone ("/vlx"): main() and the
// panel only agree on the secure path at runtime, and a request must not be
// swallowed because the caller spelled the mount point the other way. The
// longer spelling is tried first, so a prefix that already contains the secure
// path is never matched twice.
std::vector<std::string> mount_points(const std::string& prefix, const SessionConfig& cfg) {
    std::vector<std::string> out;
    if (prefix.empty() || prefix[0] != '/') return out;
    std::string secure = cfg.secure_path;
    while (!secure.empty() && secure.front() == '/') secure.erase(0, 1);
    while (!secure.empty() && secure.back() == '/') secure.pop_back();
    if (!secure.empty()) out.push_back("/" + secure + prefix);
    if (out.empty() || out[0] != prefix) out.push_back(prefix);
    return out;
}

// One request head from the uplink connection. src/http parsed the first one;
// the client pipelines every later packet onto the same socket because its
// uploadRawPool keeps the connection, so a byte stream becomes requests here.
struct MiniRequest {
    std::string method;
    std::string target;
    std::size_t content_length = 0;
    bool close_conn = false;
};

bool peek_head(const std::string& pend, MiniRequest& out, std::size_t& head_len, bool& bad) {
    bad = false;
    head_len = 0;
    const std::size_t end = pend.find("\r\n\r\n");
    if (end == std::string::npos) {
        if (pend.size() > kMaxHeadBytes) bad = true;
        return false;
    }
    const std::size_t eol = pend.find("\r\n");
    if (eol == std::string::npos || eol > end) {
        bad = true;
        return false;
    }
    const std::string line = pend.substr(0, eol);
    const std::size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) {
        bad = true;
        return false;
    }
    const std::size_t sp2 = line.find(' ', sp1 + 1);
    out.method = line.substr(0, sp1);
    out.target = (sp2 == std::string::npos) ? line.substr(sp1 + 1)
                                            : line.substr(sp1 + 1, sp2 - sp1 - 1);
    out.content_length = 0;
    out.close_conn = false;
    std::size_t pos = eol + 2;
    while (pos < end) {
        std::size_t nl = pend.find("\r\n", pos);
        if (nl == std::string::npos || nl > end) nl = end;
        const std::string header = pend.substr(pos, nl - pos);
        pos = nl + 2;
        const std::size_t colon = header.find(':');
        if (colon == std::string::npos) continue;
        const std::string name = to_lower(std::string_view(header).substr(0, colon));
        const std::string value = trim(std::string_view(header).substr(colon + 1));
        if (name == "content-length") {
            out.content_length = static_cast<std::size_t>(std::strtoull(value.c_str(), nullptr, 10));
            if (out.content_length > kMaxPostBytes) {
                bad = true;
                return false;
            }
        } else if (name == "connection" && to_lower(value).find("close") != std::string::npos) {
            out.close_conn = true;
        }
    }
    head_len = end + 4;
    return true;
}

const char kOkReply[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nCache-Control: no-store\r\n\r\nok";
const char kDownlinkHead[] = "HTTP/1.1 200 OK\r\n"
                             "Content-Type: text/event-stream\r\n"
                             "Cache-Control: no-store\r\n"
                             "X-Accel-Buffering: no\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "Connection: close\r\n"
                             "\r\n";

void reply_and_close(SSL* ssl, net::socket_t fd, const char* status) {
    std::string out = std::string("HTTP/1.1 ") + status +
                      "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    send_all(ssl, fd, out.data(), out.size());
    if (ssl) {
        SSL_shutdown(ssl);
        net::tls_free(ssl);
    }
    if (fd != net::kInvalid) net::close(fd);
}

} // namespace

// One logical XHTTP stream: an ordered uplink (many POST bodies) and a
// downlink (one chunked GET body). Every field here is guarded by mu; the two
// sockets are handed to the threads that own them and are only ever touched by
// those threads (mu guards the handover, not the I/O).
struct Session {
    std::string sid;

    std::mutex mu;
    std::condition_variable cv;

    // --- uplink -----------------------------------------------------------
    std::deque<std::string> up;             // contiguous bytes, front may be part consumed
    std::size_t up_bytes = 0;               // unconsumed bytes in up
    std::size_t up_off = 0;                 // consumed bytes in up.front()
    std::map<std::uint64_t, std::string> reorder;
    std::size_t reorder_bytes = 0;
    // The client numbers its packets from 0 within a session (dial.go keeps a
    // zero-initialised counter), and it posts concurrently, so packet 1 can
    // arrive before packet 0. Anything below next_seq is a duplicate.
    std::uint64_t next_seq = 0;
    std::int64_t last_up_ms = 0;

    // --- downlink ---------------------------------------------------------
    std::deque<std::string> down;
    std::size_t down_bytes = 0;
    net::socket_t down_fd = net::kInvalid;
    SSL* down_ssl = nullptr;
    bool down_started = false;
    bool down_gone = false;

    // Recycled block buffers (both directions). Bounded so a session cannot
    // park megabytes of empty strings.
    std::vector<std::string> spare;

    bool dead = false;
    std::int64_t last_active = 0;
};

namespace {

struct Registry {
    std::mutex mu;
    std::unordered_map<std::string, SessionPtr> map;
};

Registry& registry() {
    static Registry r;
    return r;
}

Attach& attach_slot() {
    static Attach fn = nullptr;
    return fn;
}

// Keeps one block buffer for reuse instead of allocating a fresh 16 KB per
// chunk: the relay runs for hours and the allocator would never see the pages
// again otherwise.
void recycle_locked(Session& s, std::string&& block) {
    if (s.spare.size() >= 4 || block.capacity() > 2 * kChunk) return;
    block.clear();
    s.spare.push_back(std::move(block));
}

void push_back_locked(Session& s, std::string&& data) {
    if (data.empty()) return;
    s.up_bytes += data.size();
    s.up.push_back(std::move(data));
}

// Appends one packet, honouring the sequence numbers the client puts in the
// POST path. It posts concurrently, so packets do arrive out of order.
void deliver_locked(Session& s, bool has_seq, std::uint64_t seq, std::string&& data) {
    if (!has_seq) {
        push_back_locked(s, std::move(data));
        return;
    }
    if (seq < s.next_seq) return;   // duplicate or a retried POST
    if (seq > s.next_seq) {
        if (s.reorder.size() >= kReorderCap || s.reorder_bytes + data.size() > kReorderBytes) return;
        s.reorder_bytes += data.size();
        s.reorder.emplace(seq, std::move(data));
        return;
    }
    push_back_locked(s, std::move(data));
    s.next_seq = seq + 1;
    while (true) {
        auto it = s.reorder.find(s.next_seq);
        if (it == s.reorder.end()) break;
        std::string next = std::move(it->second);
        s.reorder.erase(it);
        s.reorder_bytes -= next.size();
        s.next_seq++;
        push_back_locked(s, std::move(next));
    }
}

// A hole the client will never fill (that POST was lost) must not stall the
// stream for ever: skip to the oldest packet we do have.
void fill_gap_locked(Session& s) {
    if (s.reorder.empty()) return;
    if (now_ms() - s.last_up_ms < kGapMs) return;
    s.next_seq = s.reorder.begin()->first;
    while (true) {
        auto it = s.reorder.find(s.next_seq);
        if (it == s.reorder.end()) break;
        std::string next = std::move(it->second);
        s.reorder.erase(it);
        s.reorder_bytes -= next.size();
        s.next_seq++;
        push_back_locked(s, std::move(next));
    }
    bpb::log::debug("[xh] filled a sequence hole, session continues");
}

bool push_uplink(const SessionPtr& sess, const std::string& seq_text, bool has_seq,
                 std::string&& data) {
    if (!sess) return false;
    std::uint64_t seq = 0;
    if (has_seq) seq = std::strtoull(seq_text.c_str(), nullptr, 10);

    std::unique_lock<std::mutex> lk(sess->mu);
    if (sess->dead) return false;
    sess->last_up_ms = now_ms();
    sess->last_active = sess->last_up_ms;

    deliver_locked(*sess, has_seq, seq, std::move(data));
    sess->cv.notify_all();

    // Backpressure: an origin that cannot keep up must slow the client down
    // instead of turning into unbounded memory.
    const std::int64_t started = now_ms();
    while (sess->up_bytes > kUpQueueCap) {
        if (sess->dead) return false;
        if (now_ms() - started > kIdleMs) return false;
        sess->cv.wait_for(lk, std::chrono::milliseconds(kWaitSliceMs));
    }
    return true;
}

SessionPtr find_session(const std::string& sid) {
    std::lock_guard<std::mutex> lk(registry().mu);
    auto it = registry().map.find(sid);
    if (it == registry().map.end()) return nullptr;
    return it->second;
}

void reaper_main();

// Creates the session if it is new. Returns nullptr when the table is full.
SessionPtr acquire(const std::string& sid, bool& created) {
    created = false;
    std::lock_guard<std::mutex> lk(registry().mu);
    auto it = registry().map.find(sid);
    if (it != registry().map.end()) return it->second;
    if (registry().map.size() >= kMaxSessions) return nullptr;
    auto sess = std::make_shared<Session>();
    sess->sid = sid;
    sess->last_active = sess->last_up_ms = now_ms();
    registry().map.emplace(sid, sess);
    created = true;

    static std::once_flag once;
    std::call_once(once, [] { bpb::util::spawn_detached(&reaper_main, 128 * 1024); });
    return sess;
}

// Looks a session up, creating and binding it when it is new. Real Xray calls
// upsertSession() on *every* request because a client reuses one upload
// connection for several sessions; dropping a packet that names an unknown
// session would lose that session's VLESS header, and the client never retries
// a POST whose write succeeded.
SessionPtr session_for(const std::string& sid, const SessionConfig& cfg) {
    SessionPtr known = find_session(sid);
    if (known) return known;
    bool created = false;
    SessionPtr fresh = acquire(sid, created);
    if (fresh && created && attach_slot()) attach_slot()(fresh, cfg);
    return fresh;
}

void reaper_main() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        std::vector<SessionPtr> expired;
        {
            std::lock_guard<std::mutex> lk(registry().mu);
            const std::int64_t now = now_ms();
            for (auto it = registry().map.begin(); it != registry().map.end();) {
                const SessionPtr& sess = it->second;
                bool idle = false;
                {
                    std::lock_guard<std::mutex> sl(sess->mu);
                    idle = now - sess->last_active > kIdleMs;
                }
                if (idle) {
                    expired.push_back(sess);
                    it = registry().map.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const SessionPtr& sess : expired) {
            std::lock_guard<std::mutex> sl(sess->mu);
            sess->dead = true;
            const net::socket_t fd = sess->down_fd;
            sess->cv.notify_all();
            shutdown_both(fd);
        }
        if (!expired.empty()) {
            bpb::log::debug("[xh] reaped %zu idle session(s)", expired.size());
            bpb::util::release_free_memory();
        }
    }
}

// ---- downlink ---------------------------------------------------------------
// Owns the GET connection from the 200 onwards. Chunked framing is written
// here and nowhere else, so a chunk can never be interleaved with another.
void downlink_loop(SessionPtr sess, net::socket_t fd, SSL* ssl) {
    enable_keepalive(fd);
    bool ok = send_all(ssl, fd, kDownlinkHead, sizeof(kDownlinkHead) - 1);
    char head[32];
    while (ok) {
        std::string block;
        {
            std::unique_lock<std::mutex> lk(sess->mu);
            while (sess->down.empty() && !sess->dead) {
                sess->cv.wait_for(lk, std::chrono::milliseconds(kWaitSliceMs));
            }
            if (sess->down.empty()) break;   // dead and drained
            block = std::move(sess->down.front());
            sess->down.pop_front();
            sess->down_bytes -= block.size();
            sess->cv.notify_all();           // room for the writer
        }
        const int n = std::snprintf(head, sizeof(head), "%zx\r\n", block.size());
        ok = n > 0 && send_all(ssl, fd, head, static_cast<std::size_t>(n)) &&
             send_all(ssl, fd, block.data(), block.size()) && send_all(ssl, fd, "\r\n", 2);
        {
            std::lock_guard<std::mutex> lk(sess->mu);
            sess->last_active = now_ms();
            recycle_locked(*sess, std::move(block));
        }
    }

    // Terminal chunk: without it the client cannot tell a finished stream from
    // a truncated one and logs "unexpected EOF".
    if (ok) send_all(ssl, fd, "0\r\n\r\n", 5);

    net::socket_t my_fd = net::kInvalid;
    SSL* my_ssl = nullptr;
    {
        std::lock_guard<std::mutex> lk(sess->mu);
        my_fd = sess->down_fd;
        my_ssl = sess->down_ssl;
        sess->down_fd = net::kInvalid;
        sess->down_ssl = nullptr;
        sess->down_gone = true;
        // No downlink means no stream: the uplink has nowhere to go, so the
        // protocol thread is told to stop instead of feeding a dead pipe.
        sess->dead = true;
        sess->cv.notify_all();
    }
    if (my_ssl) {
        SSL_shutdown(my_ssl);
        net::tls_free(my_ssl);
    }
    if (my_fd != net::kInvalid) net::close(my_fd);
}

// ---- uplink ----------------------------------------------------------------
// Owns one client upload connection. src/http already parsed the first request;
// this thread answers it and then keeps serving the pipelined POSTs that follow
// on the same socket (the client pools these connections and only reads a reply
// when it sends the next packet).
void uplink_loop(SessionPtr sess, net::socket_t fd, SSL* ssl, const std::string& prefix,
                 const SessionConfig& cfg, std::string first_body, std::string first_seq,
                 bool first_has_seq, bool first_close) {
    enable_keepalive(fd);
    bool ok = push_uplink(sess, first_seq, first_has_seq, std::move(first_body));
    if (ok) ok = send_all(ssl, fd, kOkReply, sizeof(kOkReply) - 1);
    bool close_after = first_close;

    std::string pend;
    pend.reserve(kChunk);
    char buf[kChunk];
    std::int64_t last_rx = now_ms();

    while (ok && !close_after) {
        MiniRequest req;
        std::size_t head_len = 0;
        bool bad = false;
        bool ready = false;
        while (ok && !ready) {
            bad = false;
            if (peek_head(pend, req, head_len, bad)) {
                if (pend.size() >= head_len + req.content_length) {
                    ready = true;
                    break;
                }
            }
            if (bad) break;
            if (now_ms() - last_rx > kUplinkIdleMs) {
                ok = false;
                break;
            }
            net::IoResult result = net::IoResult::Error;
            const int n = net::tls_read(ssl, fd, buf, static_cast<int>(sizeof(buf)), result);
            if (n > 0) {
                last_rx = now_ms();
                pend.append(buf, static_cast<std::size_t>(n));
                if (pend.size() > kMaxHeadBytes + kMaxPostBytes) bad = true;
                continue;
            }
            if (result == net::IoResult::WouldBlock) {
                net::PollFd pfd{fd, net::kRead, 0};
                if (net::poll_fds(&pfd, 1, kWaitSliceMs) < 0) {
                    ok = false;
                    break;
                }
                continue;
            }
            ok = false;   // peer closed or a socket error
            break;
        }
        if (!ok || bad || !ready) break;

        std::string body = pend.substr(head_len, req.content_length);
        pend.erase(0, head_len + req.content_length);

        std::string target = req.target;
        const std::size_t q = target.find('?');
        if (q != std::string::npos) target = target.substr(0, q);
        std::string sid;
        std::string seq;
        bool has_seq = false;
        SessionPtr dest = nullptr;
        if (split_target(target, prefix, sid, seq, has_seq)) {
            dest = (sid == sess->sid) ? sess : session_for(sid, cfg);
        }
        if (dest && req.method == "POST") push_uplink(dest, seq, has_seq, std::move(body));
        ok = send_all(ssl, fd, kOkReply, sizeof(kOkReply) - 1);
        close_after = req.close_conn;
    }

    if (ssl) {
        SSL_shutdown(ssl);
        net::tls_free(ssl);
    }
    if (fd != net::kInvalid) net::close(fd);
}

} // namespace

void set_attach(Attach fn) { attach_slot() = std::move(fn); }

int read_uplink(const SessionPtr& sess, char* buf, int len, int timeout_ms) {
    if (!sess || !buf || len <= 0) return -1;
    std::unique_lock<std::mutex> lk(sess->mu);
    const std::int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    for (;;) {
        if (!sess->up.empty()) {
            std::string& head = sess->up.front();
            const std::size_t avail = head.size() - sess->up_off;
            const std::size_t take =
                std::min<std::size_t>(avail, static_cast<std::size_t>(len));
            std::memcpy(buf, head.data() + sess->up_off, take);
            sess->up_off += take;
            sess->up_bytes -= take;
            if (sess->up_off >= head.size()) {
                recycle_locked(*sess, std::move(head));
                sess->up.pop_front();
                sess->up_off = 0;
            }
            sess->last_active = now_ms();
            sess->cv.notify_all();   // the POST reader may be waiting for room
            return static_cast<int>(take);
        }
        if (sess->dead) return -1;
        if (now_ms() >= deadline) {
            fill_gap_locked(*sess);
            return 0;
        }
        sess->cv.wait_for(lk, std::chrono::milliseconds(kWaitSliceMs));
    }
}

bool write_downlink(const SessionPtr& sess, const char* data, std::size_t len) {
    if (!sess) return false;
    if (!data || len == 0) return true;
    std::unique_lock<std::mutex> lk(sess->mu);
    const std::int64_t started = now_ms();
    while (sess->down_bytes >= kDownQueueCap) {
        if (sess->dead || sess->down_gone) return false;
        if (now_ms() - started > kIdleMs) return false;
        sess->cv.wait_for(lk, std::chrono::milliseconds(kWaitSliceMs));
    }
    if (sess->dead) return false;
    // Reuse a recycled block when the sizes match, so an idle relay does not
    // allocate per read.
    if (!sess->spare.empty()) {
        std::string block = std::move(sess->spare.back());
        sess->spare.pop_back();
        block.assign(data, len);
        sess->down_bytes += block.size();
        sess->down.push_back(std::move(block));
    } else {
        sess->down.emplace_back(data, len);
        sess->down_bytes += len;
    }
    sess->last_active = now_ms();
    sess->cv.notify_all();
    return true;
}

void finish(const SessionPtr& sess) {
    if (!sess) return;
    {
        // Flags first, then the table: the reaper takes the two locks in the
        // opposite order, so they must never be held at the same time.
        std::lock_guard<std::mutex> lk(sess->mu);
        sess->dead = true;
        sess->cv.notify_all();
    }
    {
        std::lock_guard<std::mutex> lk(registry().mu);
        auto it = registry().map.find(sess->sid);
        if (it != registry().map.end() && it->second == sess) registry().map.erase(it);
    }
}

bool takeover(net::socket_t fd, SSL* ssl, const http::Request& req, const SessionConfig& cfg,
              const std::string& prefix) {
    if (!attach_slot()) return false;   // no protocol bound: not our traffic
    if (prefix.empty() || req.path.empty()) return false;

    std::string sid;
    std::string seq;
    bool has_seq = false;
    std::string mount;
    for (const std::string& candidate : mount_points(prefix, cfg)) {
        if (split_target(req.path, candidate, sid, seq, has_seq)) {
            mount = candidate;
            break;
        }
    }
    if (mount.empty()) return false;

    const bool is_get = req.method == "GET";
    const bool is_post = req.method == "POST";
    // stream-up/stream-one (GET with a sequence, or a single long request) are
    // deliberately not served: the client we interoperate with uses packet-up,
    // where the uplink is a series of POSTs.
    if (!is_get && !is_post) return false;
    if (is_get && has_seq) return false;

    // Upsert, exactly like xray's requestHandler: the client's upload
    // connection pool is shared between sessions, so both halves of a session
    // can arrive on connections (or in an order) we have never seen.
    SessionPtr sess = session_for(sid, cfg);
    if (!sess) {
        bpb::log::warn("[xh] session table full (%zu), refusing %s", kMaxSessions, sid.c_str());
        reply_and_close(ssl, fd, "503 Service Unavailable");
        return true;
    }

    if (is_get) {
        bool refused = false;
        {
            std::lock_guard<std::mutex> lk(sess->mu);
            if (sess->down_started || sess->dead) {
                refused = true;
            } else {
                sess->down_started = true;
                sess->down_fd = fd;
                sess->down_ssl = ssl;
            }
        }
        if (refused) {
            // A second GET for the same id, or one that arrives after the
            // session ended: the stream already has an owner.
            reply_and_close(ssl, fd, "409 Conflict");
            return true;
        }
        bpb::log::debug("[xh] downlink for %s", sid.c_str());
        if (!bpb::util::spawn_detached([sess, fd, ssl] { downlink_loop(sess, fd, ssl); },
                                       128 * 1024)) {
            // No thread means nobody owns this socket: closing it here is the
            // only alternative to leaking it, and the session must end so the
            // client retries instead of waiting on a stream that cannot run.
            bpb::log::warn("[xh] no thread for the downlink of %s, closing", sid.c_str());
            {
                std::lock_guard<std::mutex> lk(sess->mu);
                sess->down_started = false;
                sess->down_fd = net::kInvalid;
                sess->down_ssl = nullptr;
                sess->dead = true;
                sess->cv.notify_all();
            }
            reply_and_close(ssl, fd, "503 Service Unavailable");
            return true;
        }
        return true;
    }

    const std::string connection = to_lower(req.header("connection"));
    const bool close_after = connection.find("close") != std::string::npos;
    std::string body = req.body;   // src/http hands over an already parsed body
    bpb::log::debug("[xh] uplink for %s seq=%s bytes=%zu", sid.c_str(),
                    has_seq ? seq.c_str() : "-", body.size());
    if (!bpb::util::spawn_detached(
            [sess, fd, ssl, mount, cfg, body = std::move(body), seq, has_seq, close_after]() mutable {
                uplink_loop(sess, fd, ssl, mount, cfg, std::move(body), seq, has_seq, close_after);
            },
            128 * 1024)) {
        // Out of threads: nothing can answer this request, so hang up rather
        // than leaking the socket (the client's pool drops it on the error).
        bpb::log::warn("[xh] no thread for an uplink connection, closing");
        if (ssl) {
            SSL_shutdown(ssl);
            net::tls_free(ssl);
        }
        if (fd != net::kInvalid) net::close(fd);
        return true;
    }
    return true;
}

} // namespace bpb::proxy::xhttp
