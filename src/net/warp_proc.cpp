#include "net/warp_proc.h"

#include "util/util.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

#ifdef _WIN32
// POSIX-only headers; the Windows branch below provides stub implementations.
#else
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

namespace bpb::net {

#ifdef _WIN32

// Windows: supervising an external POSIX process is out of scope there, so the
// whole feature degrades to "disabled" instead of failing to link.
std::string warp_find_binary(const std::string&) { return std::string(); }
bool warp_write_config(const Store&, const std::string&, std::string& error) {
    error = "warp-rust outbound is not supported on Windows";
    return false;
}
bool warp_proc_start(Store&, std::string& error) {
    error = "warp-rust outbound is not supported on Windows";
    return false;
}
bool warp_proc_ready() { return false; }
std::string warp_proc_status() { return "unsupported on Windows"; }
void warp_proc_stop() {}
std::string warp_proc_socks_host() { return "127.0.0.1"; }
int warp_proc_socks_port() { return 0; }
socket_t warp_socks_connect(const std::string&, int, int) { return kInvalid; }

#else

namespace {

constexpr const char* kDefaultBind = "127.0.0.1";
constexpr int kDefaultPort = 11080;
// Registration cooldown guard: warp-rust reuses data/account.json, so a restart
// never re-registers. Even so, refuse to loop forever so a broken binary or a
// dead path cannot produce an endless restart storm.
constexpr int kMaxRestarts = 5;
constexpr int kRestartWindowSec = 600;

struct State {
    std::mutex mu;
    std::string binary;
    std::string config_path;
    std::string data_dir;
    std::string log_path;
    std::string bind_host = kDefaultBind;
    int port = kDefaultPort;
    pid_t pid = -1;
    std::atomic<bool> ready{false};
    std::atomic<bool> stopping{false};
    std::string last_error;
    std::thread monitor;
    std::deque<int64_t> restart_marks;
};

State& state() {
    static State s;
    return s;
}

int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool file_exists(const std::string& p) {
    struct stat st {};
    return ::stat(p.c_str(), &st) == 0;
}

bool make_dirs(const std::string& path) {
    if (path.empty()) return false;
    std::string cur;
    for (std::size_t i = 0; i < path.size(); ++i) {
        cur.push_back(path[i]);
        if (path[i] == '/' || i + 1 == path.size()) {
            if (cur == "/" || cur.empty()) continue;
            std::string dir = cur;
            while (!dir.empty() && dir.back() == '/') dir.pop_back();
            if (dir.empty()) continue;
            if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) return false;
        }
    }
    return true;
}

std::string exe_dir() {
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::string();
    buf[n] = '\0';
    std::string p(buf);
    auto slash = p.rfind('/');
    return slash == std::string::npos ? std::string() : p.substr(0, slash);
}

// Non-blocking connect with a deadline. Returns a non-blocking socket or
// kInvalid.
socket_t connect_addr(const std::string& host, int port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port);
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) return kInvalid;

    socket_t out = kInvalid;
    for (addrinfo* p = res; p; p = p->ai_next) {
        socket_t s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        int flags = ::fcntl(s, F_GETFL, 0);
        ::fcntl(s, F_SETFL, flags | O_NONBLOCK);
        bool ok = ::connect(s, p->ai_addr, p->ai_addrlen) == 0;
        if (!ok && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
            PollFd pfd{s, kWrite, 0};
            if (poll_fds(&pfd, 1, timeout_ms) > 0) {
                int soerr = 0;
                socklen_t l = sizeof(soerr);
                ::getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &l);
                ok = (soerr == 0);
            }
        }
        if (ok) {
            out = s;
            break;
        }
        ::close(s);
    }
    ::freeaddrinfo(res);
    return out;
}

bool read_exact(socket_t s, char* buf, std::size_t len, int timeout_ms) {
    std::size_t got = 0;
    while (got < len) {
        int n = static_cast<int>(::recv(s, buf + got, len - got, 0));
        if (n > 0) {
            got += static_cast<std::size_t>(n);
            continue;
        }
        if (n == 0) return false;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            PollFd pfd{s, kRead, 0};
            if (poll_fds(&pfd, 1, timeout_ms) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

bool write_all_sock(socket_t s, const char* buf, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
        int n = static_cast<int>(::send(s, buf + sent, len - sent, MSG_NOSIGNAL));
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            PollFd pfd{s, kWrite, 0};
            if (poll_fds(&pfd, 1, 5000) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

// Probes the SOCKS5 port with a full greeting so a half-open listener (the
// process is up but the tunnel is not) is not reported as ready.
bool socks_probe(const std::string& host, int port, int timeout_ms) {
    socket_t s = connect_addr(host, port, timeout_ms);
    if (s == kInvalid) return false;
    const char greet[3] = {0x05, 0x01, 0x00};
    char reply[2] = {0, 0};
    bool ok = write_all_sock(s, greet, sizeof(greet)) && read_exact(s, reply, 2, timeout_ms) &&
              reply[0] == 0x05;
    ::close(s);
    return ok;
}

void reap_and_restart(State& st);

void monitor_loop() {
    State& st = state();
    while (!st.stopping.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (st.stopping.load()) break;
        pid_t pid;
        {
            std::lock_guard<std::mutex> lk(st.mu);
            pid = st.pid;
        }
        if (pid <= 0) continue;
        int status = 0;
        pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == 0) {
            // Still alive. Probing SOCKS5 opens (and immediately abandons) a
            // connection, which warp-rust logs as a warning, so only probe while
            // readiness has not been established yet. Afterwards the child's
            // liveness is the signal: tunnel reconnects are warp-rust's own job.
            if (!st.ready.load() && socks_probe(st.bind_host, st.port, 1500)) {
                st.ready.store(true);
            }
            continue;
        }
        // Exited.
        st.ready.store(false);
        {
            std::lock_guard<std::mutex> lk(st.mu);
            st.pid = -1;
        }
        reap_and_restart(st);
    }
}

void spawn_locked(State& st);

void reap_and_restart(State& st) {
    if (st.stopping.load()) return;
    const int64_t now = now_sec();
    {
        std::lock_guard<std::mutex> lk(st.mu);
        while (!st.restart_marks.empty() && now - st.restart_marks.front() > kRestartWindowSec) {
            st.restart_marks.pop_front();
        }
        if (static_cast<int>(st.restart_marks.size()) >= kMaxRestarts) {
            st.last_error = "warp-rust keeps exiting; giving up after " +
                            std::to_string(kMaxRestarts) + " restarts in " +
                            std::to_string(kRestartWindowSec) + "s";
            return;
        }
        st.restart_marks.push_back(now);
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
    if (st.stopping.load()) return;
    std::lock_guard<std::mutex> lk(st.mu);
    if (st.pid > 0) return;
    spawn_locked(st);
}

void spawn_locked(State& st) {
    if (st.binary.empty() || st.config_path.empty()) {
        st.last_error = "warp-rust binary or config path is not configured";
        return;
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        st.last_error = "fork failed";
        return;
    }
    if (pid == 0) {
        // Child: detach from the parent's stdio and exec the external process.
#ifdef __linux__
        ::prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
        ::setsid();
        int devnull = ::open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::close(devnull);
        }
        int logfd = ::open(st.log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (logfd >= 0) {
            ::dup2(logfd, STDOUT_FILENO);
            ::dup2(logfd, STDERR_FILENO);
            ::close(logfd);
        }
        ::execl(st.binary.c_str(), "warp-rust", "--config", st.config_path.c_str(),
                static_cast<char*>(nullptr));
        ::_exit(127);
    }
    st.pid = pid;
    st.last_error.clear();
}

// Reads the memory ceiling this process actually lives under. Inside a
// container that is the cgroup limit, not /proc/meminfo, and the difference is
// the whole story on a 64 MiB box: the host may report hundreds of MiB while
// the cgroup allows 64. Returns 0 when unknown.
long read_limit_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return 0;
    std::string v;
    if (!(in >> v)) return 0;
    if (v == "max" || v.empty()) return 0;
    try {
        long long bytes = std::stoll(v);
        // cgroup v1 reports a huge sentinel when unlimited
        if (bytes <= 0 || bytes > (1LL << 50)) return 0;
        return static_cast<long>(bytes / 1024);
    } catch (...) {
        return 0;
    }
}

long read_memory_limit_kb() {
    // Prefer the cgroup this process actually lives in. Reading the mount root
    // gives the container's ceiling, which is wrong whenever the service runs
    // under a nested limit (systemd slice, a pod, or a smaller cgroup).
    std::ifstream cg("/proc/self/cgroup");
    if (cg) {
        std::string line;
        while (std::getline(cg, line)) {
            if (line.rfind("0::", 0) != 0) continue;  // cgroup v2 unified entry
            std::string rel = line.substr(3);
            if (rel.empty() || rel == "/") break;
            const long v = read_limit_file("/sys/fs/cgroup" + rel + "/memory.max");
            if (v > 0) return v;
            break;
        }
    }
    long v = read_limit_file("/sys/fs/cgroup/memory.max");  // cgroup v2 root
    if (v > 0) return v;
    return read_limit_file("/sys/fs/cgroup/memory/memory.limit_in_bytes");  // cgroup v1
}

std::string toml_escape(const std::string& v) {
    std::string out;
    for (char c : v) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

} // namespace

std::string warp_find_binary(const std::string& configured) {
    if (!configured.empty() && file_exists(configured)) return configured;

    const std::string dir = exe_dir();
    const char* names[] = {"warp-rust", "warp-rust.exe"};
    if (!dir.empty()) {
        for (const char* n : names) {
            const std::string cand = dir + "/" + n;
            if (file_exists(cand)) return cand;
        }
    }
    for (const char* n : names) {
        const std::string cand = std::string("./") + n;
        if (file_exists(cand)) return cand;
    }
    // Fall back to $PATH.
    const char* path = ::getenv("PATH");
    if (path) {
        std::string s(path);
        std::size_t start = 0;
        while (start <= s.size()) {
            std::size_t end = s.find(':', start);
            if (end == std::string::npos) end = s.size();
            if (end > start) {
                for (const char* n : names) {
                    const std::string cand = s.substr(start, end - start) + "/" + n;
                    if (file_exists(cand)) return cand;
                }
            }
            start = end + 1;
        }
    }
    return std::string();
}

bool warp_write_config(const Store& store, const std::string& path, std::string& error) {
    const auto& kv = store.kv();
    nlohmann::json wg = nlohmann::json::object();
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object()) wg = kv["wgOutbound"];

    const std::string bind_host = wg.value("bindHost", std::string(kDefaultBind));
    const int port = wg.value("socksPort", kDefaultPort);
    if (port <= 0 || port > 65535) {
        error = "wgOutbound.socksPort out of range";
        return false;
    }
    const int mtu = wg.value("mtu", 1280);

    // Concurrency budget. warp-rust pre-allocates 2 x tcp_buffer_size + 2 x
    // relay_buffer_size per *established* connection, and the container also
    // pays kernel socket buffers plus page cache for the same streams, so the
    // real cost per active connection measures closer to 600-800 KiB rather
    // than the 256 KiB the config alone suggests. Measured on a 64 MiB cgroup:
    // 8 concurrent streams ~0.7 MiB total, 16 streams ~12.7 MiB, 32 streams hit
    // the ceiling and the kernel started killing processes.
    // Hence: budget one connection per 4 MiB of the ceiling.
    const long limit_kb = read_memory_limit_kb();
    int max_conn = wg.value("maxConnections", 0);
    if (max_conn <= 0) {
        max_conn = limit_kb > 0 ? static_cast<int>(limit_kb / 4096) : 128;
    }
    if (limit_kb > 0) {
        // Never exceed what the ceiling can actually carry, even if the panel
        // asks for more: oversubscribing only moves the failure to the OOM
        // killer, which does not spare the tunnel process.
        const int safe = static_cast<int>(limit_kb / 4096);
        if (max_conn > safe) max_conn = safe;
    }
    if (max_conn < 8) max_conn = 8;

    // On small boxes shrink the per-connection TCP buffer too: it dominates the
    // per-connection cost and 64 KiB still sustains multi-Mbit streams.
    const int tcp_buf = limit_kb > 0 && limit_kb <= 131072 ? 65536 : 262144;
    const int relay_buf = limit_kb > 0 && limit_kb <= 131072 ? 32768 : 65536;

    // warp-rust validates max_pending_dials <= max_concurrent_connections.
    const int pending = max_conn < 128 ? max_conn : 128;

    std::string data_dir = wg.value("dataDir", std::string());
    if (data_dir.empty()) data_dir = store.dir() + "/warp";
    if (!make_dirs(data_dir)) {
        error = "cannot create warp data dir " + data_dir;
        return false;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot write " + path;
        return false;
    }
    out << "# Generated by bpb. Edits are overwritten on every start.\n"
        << "[server]\n"
        << "bind = \"" << toml_escape(bind_host) << ":" << port << "\"\n\n"
        << "[logging]\n"
        << "level = \"warn,warp_rust=info,warp_wireguard_gen=info,wireguard_netstack=warn\"\n"
        << "format = \"compact\"\n\n"
        << "[warp]\n"
        << "data_dir = \"" << toml_escape(data_dir) << "\"\n"
        << "device_model = \"bpb-panel-cpp\"\n"
        << "mtu = " << mtu << "\n"
        << "refresh_interval = \"24h\"\n"
        // Never let recovery hammer the registration endpoint: warp-rust reuses
        // data/account.json and this cooldown bounds the worst case.
        << "register_cooldown = \"30m\"\n"
        << "tcp_buffer_size = " << tcp_buf << "\n\n"
        << "[health]\n"
        << "interval = \"30s\"\n"
        << "timeout = \"8s\"\n\n"
        << "[metrics]\n"
        << "enabled = false\n\n"
        << "[limits]\n"
        << "max_concurrent_connections = " << max_conn << "\n"
        << "max_pending_dials = " << pending << "\n"
        << "relay_buffer_size = " << relay_buf << "\n";
    out.flush();
    if (!out) {
        error = "write failed for " + path;
        return false;
    }
    return true;
}

bool warp_proc_start(Store& store, std::string& error) {
    State& st = state();
    const auto& kv = store.kv();
    nlohmann::json wg = nlohmann::json::object();
    if (kv.contains("wgOutbound") && kv["wgOutbound"].is_object()) wg = kv["wgOutbound"];

    if (!wg.value("enabled", false)) {
        error = "wireguard outbound disabled";
        return false;
    }

    std::string binary = warp_find_binary(wg.value("binary", std::string()));
    if (binary.empty()) {
        error = "warp-rust binary not found (set wgOutbound.binary or ship it next to bpb)";
        return false;
    }
    if (!make_dirs(store.dir())) {
        error = "cannot create data dir";
        return false;
    }

    const std::string cfg = store.dir() + "/warp-rust.toml";
    if (!warp_write_config(store, cfg, error)) return false;

    {
        std::lock_guard<std::mutex> lk(st.mu);
        if (st.pid > 0) {
            error = "already running";
            return true;
        }
        st.stopping.store(false);
        st.binary = binary;
        st.config_path = cfg;
        st.bind_host = wg.value("bindHost", std::string(kDefaultBind));
        st.port = wg.value("socksPort", kDefaultPort);
        st.log_path = store.dir() + "/warp-rust.log";
        st.last_error.clear();
        spawn_locked(st);
    }

    // Wait for the SOCKS5 listener. First start may need to register, which
    // costs a couple of round trips, so allow a generous window.
    const int deadline_ms = 25000;
    for (int waited = 0; waited < deadline_ms; waited += 250) {
        if (socks_probe(st.bind_host, st.port, 800)) {
            st.ready.store(true);
            error.clear();
            std::lock_guard<std::mutex> lk(st.mu);
            st.monitor = std::thread(monitor_loop);
            st.monitor.detach();
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    error = "warp-rust did not expose SOCKS5 on " + st.bind_host + ":" +
            std::to_string(st.port) + " within " + std::to_string(deadline_ms / 1000) + "s";
    return false;
}

bool warp_proc_ready() { return state().ready.load(); }

std::string warp_proc_status() {
    State& st = state();
    std::lock_guard<std::mutex> lk(st.mu);
    if (st.pid <= 0 && st.last_error.empty()) return "stopped";
    if (st.pid <= 0) return "failed: " + st.last_error;
    std::string s = st.ready.load() ? "ready" : "starting";
    s += " (pid " + std::to_string(st.pid) + ", socks " + st.bind_host + ":" +
         std::to_string(st.port) + ")";
    if (!st.last_error.empty()) s += " [" + st.last_error + "]";
    return s;
}

void warp_proc_stop() {
    State& st = state();
    st.stopping.store(true);
    st.ready.store(false);
    pid_t pid;
    {
        std::lock_guard<std::mutex> lk(st.mu);
        pid = st.pid;
        st.pid = -1;
    }
    if (pid > 0) {
        ::kill(pid, SIGTERM);
        for (int i = 0; i < 20; ++i) {
            int status = 0;
            if (::waitpid(pid, &status, WNOHANG) != 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        ::kill(pid, SIGKILL);
    }
}

std::string warp_proc_socks_host() {
    State& st = state();
    std::lock_guard<std::mutex> lk(st.mu);
    return st.bind_host.empty() ? std::string(kDefaultBind) : st.bind_host;
}

int warp_proc_socks_port() {
    State& st = state();
    std::lock_guard<std::mutex> lk(st.mu);
    return st.port > 0 ? st.port : kDefaultPort;
}

socket_t warp_socks_connect(const std::string& host, int port, int timeout_ms) {
    const std::string proxy_host = warp_proc_socks_host();
    const int proxy_port = warp_proc_socks_port();
    socket_t s = connect_addr(proxy_host, proxy_port, timeout_ms);
    if (s == kInvalid) return kInvalid;

    const char greet[3] = {0x05, 0x01, 0x00};
    char reply[2] = {0, 0};
    if (!write_all_sock(s, greet, sizeof(greet)) || !read_exact(s, reply, 2, timeout_ms) ||
        reply[0] != 0x05 || reply[1] != 0x00) {
        ::close(s);
        return kInvalid;
    }

    std::string req;
    req.push_back(static_cast<char>(0x05));
    req.push_back(static_cast<char>(0x01));
    req.push_back(static_cast<char>(0x00));

    in_addr v4 {};
    in6_addr v6 {};
    if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        req.push_back(static_cast<char>(0x01));
        req.append(reinterpret_cast<const char*>(&v4), 4);
    } else if (::inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
        req.push_back(static_cast<char>(0x04));
        req.append(reinterpret_cast<const char*>(&v6), 16);
    } else {
        if (host.size() > 255) {
            ::close(s);
            return kInvalid;
        }
        req.push_back(static_cast<char>(0x03));
        req.push_back(static_cast<char>(host.size()));
        req.append(host);
    }
    req.push_back(static_cast<char>((port >> 8) & 0xFF));
    req.push_back(static_cast<char>(port & 0xFF));

    if (!write_all_sock(s, req.data(), req.size())) {
        ::close(s);
        return kInvalid;
    }
    // Reply: VER REP RSV ATYP [ADDR] PORT. Read the fixed 4 bytes first.
    char head[4] = {0, 0, 0, 0};
    if (!read_exact(s, head, 4, timeout_ms) || head[0] != 0x05 || head[1] != 0x00) {
        ::close(s);
        return kInvalid;
    }
    std::size_t addr_len = 0;
    if (head[3] == 0x01) addr_len = 4;
    else if (head[3] == 0x04) addr_len = 16;
    else if (head[3] == 0x03) {
        char l = 0;
        if (!read_exact(s, &l, 1, timeout_ms)) {
            ::close(s);
            return kInvalid;
        }
        addr_len = static_cast<std::size_t>(static_cast<unsigned char>(l));
    } else {
        ::close(s);
        return kInvalid;
    }
    std::string rest(addr_len + 2, '\0');
    if (!read_exact(s, rest.data(), rest.size(), timeout_ms)) {
        ::close(s);
        return kInvalid;
    }
    return s;
}

#endif // _WIN32

} // namespace bpb::net
