#include "net/wg_stack.h"
#include "util/log.h"

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace bpb::net {

namespace {

#ifdef _WIN32
using os_socket = SOCKET;
constexpr os_socket kBadSocket = INVALID_SOCKET;
#else
using os_socket = int;
constexpr os_socket kBadSocket = -1;
#endif

std::uint32_t now_ms() {
    using namespace std::chrono;
    static const auto start = steady_clock::now();
    return static_cast<std::uint32_t>(
        duration_cast<milliseconds>(steady_clock::now() - start).count());
}

bool resolve_v4(const std::string& host, std::uint32_t& out_ip, std::string& error) {
    // Literal first.
    in_addr a{};
    if (inet_pton(AF_INET, host.c_str(), &a) == 1) {
        out_ip = ntohl(a.s_addr);
        return true;
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        error = "cannot resolve " + host;
        return false;
    }
    sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    out_ip = ntohl(sin->sin_addr.s_addr);
    freeaddrinfo(res);
    return true;
}

} // namespace

// ---------------------------------------------------------------------------

struct WgStack::Impl {
    wg::Device device;
    struct netif nif{};
    bool started = false;
    bool netif_added = false;
    std::uint32_t nif_ip4 = 0;
    int nif_mtu = 1280;
    std::recursive_mutex mtx;

    os_socket udp = kBadSocket;
    sockaddr_storage peer{};
    int peer_len = 0;
    std::uint32_t last_attempt_ms = 0;
    std::uint32_t backoff_ms = 500;

    std::mutex cv_mtx;
    std::condition_variable cv;

    // Background driver, see start_driver().
    std::thread driver;
    std::atomic<bool> driver_stop{false};
};

// WireGuard -> lwIP
static void on_tunnel_packet(const unsigned char* data, std::size_t len) {
    if (len < 20) return;
    if (bpb::log::enabled(bpb::log::kTrace)) {
        const auto tms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now().time_since_epoch())
                             .count() % 1000000;
        std::fprintf(stderr, "[wg %ld] rx ip %zu proto=%u flags=%02x%02x\n",
                     static_cast<long>(tms), len, static_cast<unsigned>(data[9]), data[6], data[7]);
    }
    auto& impl = WgStack::instance().impl();
    std::lock_guard<std::recursive_mutex> lk(impl.mtx);
    struct pbuf* p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(len), PBUF_RAM);
    if (!p) return;
    if (pbuf_take(p, data, static_cast<u16_t>(len)) != ERR_OK) {
        pbuf_free(p);
        return;
    }
    if (impl.nif.input && impl.nif.input(p, &impl.nif) != ERR_OK) pbuf_free(p);
}

WgStack::WgStack() : impl_(new Impl()) {}
WgStack::~WgStack() { stop(); }

WgStack& WgStack::instance() {
    static WgStack stack;
    return stack;
}

bool WgStack::start(const wg::PeerConfig& cfg, std::string& error) {
    auto& s = *impl_;
    std::lock_guard<std::recursive_mutex> lk(s.mtx);
    if (s.started) return true;

    if (!s.device.configure(cfg, error)) return false;
    s.device.set_on_packet(&on_tunnel_packet);

    // lwip_init() is not idempotent: it resets the timeout lists and the netif
    // list while a previous netif may still be registered. It only has to run
    // once per process; the netif itself is added and removed per start/stop.
    static bool lwip_ready = false;
    if (!lwip_ready) {
        lwip_init();
        lwip_ready = true;
    }

    // netif_add() zeroes output/mtu/flags *before* calling the init callback, so
    // everything has to be set inside netif_init below; values assigned on the
    // netif before the call are silently discarded.
    std::uint32_t v4 = s.device.local_v4();
    if (v4 == 0) v4 = 0xAC100002;  // 172.16.0.2, the WARP default
    s.nif_ip4 = v4;
    s.nif_mtu = s.device.mtu();

    // 0.0.0.0/0 netmask + our own address as gateway makes every destination
    // "on-link", which is exactly right for a point-to-point tunnel.
    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip, (v4 >> 24) & 0xFF, (v4 >> 16) & 0xFF, (v4 >> 8) & 0xFF, v4 & 0xFF);
    IP4_ADDR(&mask, 0, 0, 0, 0);
    IP4_ADDR(&gw, (v4 >> 24) & 0xFF, (v4 >> 16) & 0xFF, (v4 >> 8) & 0xFF, v4 & 0xFF);

    if (!netif_add(&s.nif, &ip, &mask, &gw, nullptr,
                   [](struct netif* n) -> err_t {
                       auto& st = WgStack::instance().impl();
                       n->name[0] = 'w';
                       n->name[1] = 'g';
                       n->mtu = static_cast<u16_t>(st.nif_mtu);
                       n->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
                       n->output = [](struct netif*, struct pbuf* p, const ip4_addr_t*) -> err_t {
                           unsigned char buf[1600];
                           std::size_t off = 0;
                           for (struct pbuf* q = p; q && off < sizeof(buf); q = q->next) {
                               std::size_t seg = q->len;
                               if (off + seg > sizeof(buf)) seg = sizeof(buf) - off;
                               std::memcpy(buf + off, q->payload, seg);
                               off += seg;
                           }
                           auto& inner = WgStack::instance().impl();
                           const bool sent = inner.device.send_packet(buf, off);
                           const auto tms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::steady_clock::now().time_since_epoch())
                                                .count() % 1000000;
                            if (bpb::log::enabled(bpb::log::kTrace)) {
                                std::fprintf(stderr,
                                             "[wg %ld] tx ip %zu proto=%u ihl=%u tot=%u "
                                             "seq=%02x%02x%02x%02x doff=%u %s\n",
                                             static_cast<long>(tms), off,
                                             off > 9 ? static_cast<unsigned>(buf[9]) : 0u,
                                             off > 0 ? (unsigned)(buf[0] & 0x0F) : 0u,
                                             off > 3 ? (unsigned)((buf[2] << 8) | buf[3]) : 0u,
                                             off > 23 ? (unsigned)buf[24] : 0u,
                                             off > 23 ? (unsigned)buf[25] : 0u,
                                             off > 23 ? (unsigned)buf[26] : 0u,
                                             off > 23 ? (unsigned)buf[27] : 0u,
                                             off > 32 ? (unsigned)(buf[32] >> 4) : 0u,
                                             sent ? "ok" : "DROPPED");
                                if (off > 60) {
                                    const unsigned ihl = (unsigned)(buf[0] & 0x0F) * 4u;
                                    const unsigned doff =
                                        (unsigned)(buf[ihl + 12] >> 4) * 4u;
                                    const unsigned dstart = ihl + doff;
                                    std::fprintf(stderr, "[wg]     payload@%u:", dstart);
                                    for (unsigned k = dstart; k < off && k < dstart + 8; ++k)
                                        std::fprintf(stderr, " %02x", (unsigned)buf[k]);
                                    std::fprintf(stderr, "\n");
                                }
                            }
                            return sent ? ERR_OK : ERR_IF;
                       };
                       return ERR_OK;
                   }, ip_input)) {
        error = "netif_add failed";
        return false;
    }
    netif_set_default(&s.nif);
    netif_set_up(&s.nif);

    s.netif_added = true;
    s.started = true;
    return true;
}

void WgStack::stop() {
    // Join before taking the lock: the driver calls pump(), which takes it.
    stop_driver();
    auto& s = *impl_;
    std::lock_guard<std::recursive_mutex> lk(s.mtx);

    // Release everything start()/open_udp() acquired. Leaving the netif
    // registered and the UDP socket open was harmless while the stack could
    // only ever start once per process, but the panel now restarts it whenever
    // the WireGuard settings change -- without this the netif list grew by one
    // entry per restart and the old socket leaked until the process exited.
    if (s.netif_added) {
        netif_remove(&s.nif);
        netif_set_default(nullptr);
        s.netif_added = false;
    }
    if (s.udp != kBadSocket) {
#ifdef _WIN32
        closesocket(s.udp);
#else
        ::close(s.udp);
#endif
        s.udp = kBadSocket;
    }
    // Drop the transport session so a later start() performs a full handshake
    // instead of reusing keys bound to the old socket.
    s.device.reset_session();
    s.peer_len = 0;
    s.last_attempt_ms = 0;
    s.backoff_ms = 500;
    s.started = false;
}

bool WgStack::running() const { return impl_->started; }

bool WgStack::ready() {
    auto& s = *impl_;
    bool up = s.started && s.device.has_session() && !s.device.expired();
    if (up) s.backoff_ms = 500;  // reset once a session is live
    return up;
}

bool WgStack::open_udp(const std::string& endpoint, std::string& error) {
    auto& s = *impl_;
    auto colon = endpoint.rfind(':');
    if (colon == std::string::npos) {
        error = "endpoint must be host:port";
        return false;
    }
    std::string host = endpoint.substr(0, colon);
    int port = std::atoi(endpoint.c_str() + colon + 1);

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        error = "cannot resolve endpoint " + host;
        return false;
    }
    std::memcpy(&s.peer, res->ai_addr, res->ai_addrlen);
    s.peer_len = static_cast<int>(res->ai_addrlen);
    freeaddrinfo(res);

    s.udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s.udp == kBadSocket) {
        error = "udp socket failed";
        return false;
    }
    if (::connect(s.udp, reinterpret_cast<sockaddr*>(&s.peer), s.peer_len) != 0) {
        error = "udp connect failed";
        return false;
    }
    // Non-blocking reads: pump() must never stall.
#ifdef _WIN32
    u_long nonblocking = 1;
    ioctlsocket(s.udp, FIONBIO, &nonblocking);
#else
    int flags = fcntl(s.udp, F_GETFL, 0);
    fcntl(s.udp, F_SETFL, flags | O_NONBLOCK);
#endif

    s.device.set_send([&s](const unsigned char* d, std::size_t n) {
        return ::send(s.udp, reinterpret_cast<const char*>(d), static_cast<int>(n), 0) ==
               static_cast<int>(n);
    });

    // The endpoint's reply lands on this socket. Nothing else calls pump() until
    // a connect() is already in flight, and connect() is only reached once
    // ready() is true - so without a driver the handshake could never complete.
    start_driver();
    return true;
}

void WgStack::start_driver() {
    auto& s = *impl_;
    if (s.driver.joinable()) return;
    s.driver_stop.store(false);
    s.driver = std::thread([] {
        auto& st = WgStack::instance().impl();
        unsigned long long last_rx_seen = 0;
        unsigned long long last_tx_seen = 0;
        std::uint32_t last_progress_ms = 0;
        while (!st.driver_stop.load()) {
            WgStack::instance().pump();
            if (!WgStack::instance().ready()) {
                std::string ignored;
                WgStack::instance().ensure_tunnel(ignored);
            } else {
                // Rx-stall watchdog. Cloudflare's WARP silently invalidates a
                // session after a while: it keeps accepting our datagrams and
                // answers nothing, while have_keys_ stays true, so nothing ever
                // retried the handshake and the tunnel stayed dead until restart
                // (observed as "first request works, everything after times out",
                // with tx_bytes climbing and rx_bytes frozen). Whenever the peer
                // stops answering for 15s while we are sending, drop the session
                // and let ensure_tunnel() start a fresh handshake.
                const unsigned long long rx = st.device.rx_bytes();
                const unsigned long long tx = st.device.tx_bytes();
                const std::uint32_t now = wg::monotonic_ms();
                if (rx != last_rx_seen) {
                    last_rx_seen = rx;
                    last_progress_ms = now;
                    last_tx_seen = tx;
                } else if (last_progress_ms != 0 && now - last_progress_ms > 15000 &&
                           tx > last_tx_seen) {
                    // We transmitted during the silence: the peer is not
                    // answering, which is how WARP drops an invalidated session.
                    // 15s was far too slow - a TLS handshake crossing the stalled
                    // window blew the client's timeout before the recovery kicked
                    // in, so requests that would have worked still failed.
                    st.device.reset_session();
                    st.backoff_ms = 500;
                    last_progress_ms = now;
                    last_tx_seen = tx;
                } else if (last_progress_ms == 0) {
                    last_progress_ms = now;
                    last_tx_seen = tx;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
}

void WgStack::stop_driver() {
    auto& s = *impl_;
    s.driver_stop.store(true);
    if (s.driver.joinable()) s.driver.join();
}

bool WgStack::ensure_tunnel(std::string& error) {
    auto& s = *impl_;
    std::lock_guard<std::recursive_mutex> lk(s.mtx);
    if (!s.started) {
        error = "wireguard stack not started";
        return false;
    }
    if (s.device.has_session() && !s.device.expired()) return true;

    // Back off between attempts: the endpoint rate-limits repeated handshakes,
    // and re-initiating invalidates any response already in flight.
    std::uint32_t now = wg::monotonic_ms();
    if (s.last_attempt_ms != 0 && (now - s.last_attempt_ms) < s.backoff_ms) {
        error = "handshake backoff";
        return false;
    }
    bool ok = s.device.initiate(error);
    if (ok) {
        s.last_attempt_ms = now;
        s.backoff_ms = std::min<std::uint32_t>(s.backoff_ms * 2, 8000u);
    } else {
        s.last_attempt_ms = now;
    }
    return ok;
}

void WgStack::pump() {
    auto& s = *impl_;

    // Serialise the WHOLE pump, including the UDP drain. Several threads call
    // this (the background driver, every connect() that is waiting, and any
    // relay that keeps the stack alive), and wg::Device is not thread safe: two
    // threads inside handle_datagram() can interleave the replay counter and
    // session-key updates, which silently drops datagrams. That shows up as a
    // mostly-working tunnel that occasionally loses the final record - e.g. a
    // TLS close_notify, which makes strict clients report a truncated stream.
    // The mutex is recursive, so the callbacks taking it again is fine.
    std::lock_guard<std::recursive_mutex> lk(s.mtx);

    if (s.udp != kBadSocket) {
        for (int i = 0; i < 32; ++i) {
            unsigned char buf[2048];
            int n = static_cast<int>(recvfrom(s.udp, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                              nullptr, nullptr));
            if (n <= 0) break;
            s.device.handle_datagram(buf, static_cast<std::size_t>(n));
        }
    }

    s.device.tick();
    sys_check_timeouts();
}

unsigned long long WgStack::rx_bytes() { return impl_->device.rx_bytes(); }
unsigned long long WgStack::tx_bytes() { return impl_->device.tx_bytes(); }

std::string WgStack::describe() {
    auto& s = *impl_;
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "session=%s tx=%llu rx=%llu netif=%s ip=%s gw=%s",
                  s.device.has_session() ? "up" : "down", s.device.tx_bytes(), s.device.rx_bytes(),
                  s.nif.flags & NETIF_FLAG_UP ? "up" : "down",
                  ip4addr_ntoa(netif_ip4_addr(&s.nif)), ip4addr_ntoa(netif_ip4_gw(&s.nif)));
    return buf;
}

// ---------------------------------------------------------------------------

struct WgConnection::State {
    tcp_pcb* pcb = nullptr;
    bool connected = false;
    bool closed = false;
    bool errored = false;
    std::vector<char> rx;
    std::mutex m;
    std::condition_variable cv;
};

namespace {

err_t on_connected(void* arg, struct tcp_pcb*, err_t err) {
    auto* st = static_cast<WgConnection::State*>(arg);
    std::lock_guard<std::mutex> lk(st->m);
    st->connected = (err == ERR_OK);
    if (!st->connected) st->errored = true;
    st->cv.notify_all();
    return ERR_OK;
}

err_t on_recv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) {
    auto* st = static_cast<WgConnection::State*>(arg);
    std::lock_guard<std::mutex> lk(st->m);
    if (err != ERR_OK) {
        st->errored = true;
        st->cv.notify_all();
        return ERR_OK;
    }
    if (!p) {  // remote closed
        st->closed = true;
        st->cv.notify_all();
        tcp_recv(pcb, nullptr);
        return ERR_OK;
    }
    for (struct pbuf* q = p; q; q = q->next) {
        const char* start = static_cast<const char*>(q->payload);
        st->rx.insert(st->rx.end(), start, start + q->len);
    }
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    st->cv.notify_all();
    return ERR_OK;
}

void on_err(void* arg, err_t) {
    auto* st = static_cast<WgConnection::State*>(arg);
    std::lock_guard<std::mutex> lk(st->m);
    st->errored = true;
    st->cv.notify_all();
}

} // namespace

WgConnection::WgConnection(void* pcb) : state_(new State()) {
    state_->pcb = static_cast<tcp_pcb*>(pcb);
    if (state_->pcb) {
        tcp_arg(state_->pcb, state_.get());
        tcp_recv(state_->pcb, on_recv);
        tcp_err(state_->pcb, on_err);
    }
}

WgConnection::~WgConnection() {
    close();
    // Let lwIP finish any in-flight callbacks before the state goes away.
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

int WgConnection::read(char* buf, int len, int timeout_ms) {
    auto& st = *state_;
    std::unique_lock<std::mutex> lk(st.m);
    if (st.rx.empty() && !st.closed && !st.errored) {
        st.cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
            return !st.rx.empty() || st.closed || st.errored;
        });
    }
    if (!st.rx.empty()) {
        int n = static_cast<int>(std::min<std::size_t>(st.rx.size(), static_cast<std::size_t>(len)));
        std::memcpy(buf, st.rx.data(), static_cast<std::size_t>(n));
        st.rx.erase(st.rx.begin(), st.rx.begin() + n);
        return n;
    }
    if (st.closed || st.errored) return -1;
    return 0;
}

int WgConnection::write(const char* buf, int len) {
    auto& st = *state_;
    if (!st.pcb) return -1;
    // lwIP is not reentrant: the background driver runs pump() (timers, netif
    // output) on this very pcb, so queueing a segment outside the stack lock
    // races it. Symptom was an HTTPS stream that completed the handshake and
    // then lost the client's Finished/request, so the origin closed without
    // answering - roughly four failures in five, while plain HTTP (single small
    // write, nothing else in flight) worked.
    auto& stack = WgStack::instance().impl();
    std::lock_guard<std::recursive_mutex> lk(stack.mtx);
    err_t e = tcp_write(st.pcb, buf, static_cast<u16_t>(len), TCP_WRITE_FLAG_COPY);
    if (bpb::log::enabled(bpb::log::kTrace))
        std::fprintf(stderr, "[wg] tcp_write(%d) -> %d sndbuf=%u\n", len, static_cast<int>(e),
                     static_cast<unsigned>(tcp_sndbuf(st.pcb)));
    if (e != ERR_OK) return -1;
    tcp_output(st.pcb);
    return len;
}

void WgConnection::close() {
    auto& st = *state_;
    if (!st.pcb) return;
    auto& stack = WgStack::instance().impl();
    std::lock_guard<std::recursive_mutex> lk(stack.mtx);
    tcp_arg(st.pcb, nullptr);
    tcp_recv(st.pcb, nullptr);
    tcp_err(st.pcb, nullptr);
    // tcp_close() can refuse (ERR_MEM) when the send queue still holds data or
    // the peer's window is closed. Ignoring that left the pcb allocated forever:
    // the stack served exactly one connection and then every later connect()
    // failed, which is the "first request works, the rest time out" pattern.
    // tcp_abort() always releases it.
    if (tcp_close(st.pcb) != ERR_OK) tcp_abort(st.pcb);
    st.pcb = nullptr;
}

bool WgConnection::valid() const { return state_ && state_->pcb && !state_->errored; }

std::unique_ptr<WgConnection> WgStack::connect(const std::string& host, int port, int timeout_ms,
                                                std::string& error) {
    auto& s = *impl_;
    if (!s.started) {
        error = "wireguard stack not started";
        return nullptr;
    }

    std::uint32_t ip = 0;
    if (!resolve_v4(host, ip, error)) return nullptr;

    // Reuse an existing session; only handshake when there is none. A failure
    // here is not fatal on its own: the caller loop retries via pump().
    if (!s.device.has_session() || s.device.expired()) {
        std::string tunnel_error;
        ensure_tunnel(tunnel_error);
    }

    std::unique_ptr<WgConnection> conn;
    tcp_pcb* pcb = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(s.mtx);
        pcb = tcp_new();
        if (!pcb) {
            error = "tcp_new failed";
            return nullptr;
        }

        ip_addr_t addr;
        IP_ADDR4(&addr, (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);

        conn.reset(new WgConnection(pcb));

        err_t e = tcp_connect(pcb, &addr, static_cast<u16_t>(port), on_connected);
        if (e != ERR_OK) {
            // conn->close() already runs tcp_close() and, when that refuses,
            // tcp_abort(); either way the pcb is freed and st.pcb is cleared.
            // Calling tcp_abort(pcb) on the raw pointer afterwards was a
            // use-after-free: lwIP's tcp_abandon() freed the pcb a second time
            // and glibc aborted the whole process with
            //   "free(): double free detected in tcache 2"
            // Any dial that failed at tcp_connect (no route inside the WARP
            // netif, ERR_MEM under load) therefore killed bpb mid-request, which
            // is what truncated large uploads at a few hundred KB.
            conn->close();
            error = std::string("tcp_connect failed: ") + lwip_strerr(e);
            return nullptr;
        }
    }

    // Wait for the TCP handshake to complete.
    std::uint32_t deadline = now_ms() + static_cast<std::uint32_t>(timeout_ms);
    while (now_ms() < deadline) {
        pump();
        {
            std::lock_guard<std::mutex> lk2(conn->state().m);
            if (conn->state().connected) return conn;
            if (conn->state().errored) {
                error = "connect rejected";
                return nullptr;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    error = "connect timeout";
    return nullptr;
}

} // namespace bpb::net
