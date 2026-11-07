#include "app/restart.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <thread>
#endif

namespace bpb::app {

namespace {

#ifndef _WIN32

struct ProcInfo {
    long pid = 0;
    std::vector<std::string> argv;
    std::string cwd;
    std::string cgroup;
};

std::string read_all(const std::string& path) {
    std::string out;
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return out;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
}

std::string base_name(const std::string& p) {
    const auto slash = p.find_last_of('/');
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

// True when this argv looks like a bpb process. The binary is also installed as
// /usr/local/lib/<unit>/bpb, so the basename is the only stable part.
bool looks_like_bpb(const std::vector<std::string>& argv) {
    if (argv.empty()) return false;
    std::string exe = base_name(argv[0]);
    // "bpb", "bpb.exe", "bpb-linux-amd64-all" all count; "bpbfoo" does not,
    // otherwise an unrelated binary would be restarted.
    if (exe.size() < 3) return false;
    if (exe.compare(0, 3, "bpb") != 0) return false;
    const char next = exe.size() > 3 ? exe[3] : '\0';
    return next == '\0' || next == '-' || next == '.' || next == '_';
}

ProcInfo read_proc(long pid) {
    ProcInfo info;
    info.pid = pid;
    const std::string base = "/proc/" + std::to_string(pid) + "/";

    // argv is NUL separated. Keep it byte-exact: the restart must reuse the
    // original parameters, not a reconstruction.
    const std::string raw = read_all(base + "cmdline");
    std::string cur;
    for (char c : raw) {
        if (c == '\0') {
            info.argv.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) info.argv.push_back(cur);

    char link[4096];
    const ssize_t n = ::readlink((base + "cwd").c_str(), link, sizeof(link) - 1);
    if (n > 0) {
        link[n] = '\0';
        info.cwd = link;
    }
    info.cgroup = read_all(base + "cgroup");
    return info;
}

std::vector<ProcInfo> discover_bpb() {
    std::vector<ProcInfo> found;
    DIR* dir = ::opendir("/proc");
    if (!dir) return found;
    const long self = static_cast<long>(::getpid());
    while (dirent* ent = ::readdir(dir)) {
        const char* name = ent->d_name;
        if (name[0] < '0' || name[0] > '9') continue;
        const long pid = std::strtol(name, nullptr, 10);
        if (pid == self) continue;   // never restart ourselves
        ProcInfo info = read_proc(pid);
        if (!looks_like_bpb(info.argv)) continue;
        // A stale /proc entry (process died between readdir and read) has no
        // argv; skip it rather than reporting a pid that cannot be restarted.
        if (info.argv.empty()) continue;
        found.push_back(std::move(info));
    }
    ::closedir(dir);
    std::sort(found.begin(), found.end(),
              [](const ProcInfo& a, const ProcInfo& b) { return a.pid < b.pid; });
    return found;
}

// The systemd unit that owns this process, or empty when it was started by hand.
// Read from the cgroup membership rather than `systemctl status <pid>`: the
// latter is not available in every container and its output is not stable.
std::string unit_from_cgroup(const std::string& raw) {
    // "0::/system.slice/bpb.service\n" -> "bpb.service"
    // User units nest deeper (".../user@1000.service/app.slice/bpb.service"),
    // so take the LAST `.service` component, which is the actual unit.
    //
    // The trailing newline matters: /proc/PID/cgroup ends with one, and without
    // trimming, the last component is "bpb.service\n", which does not end in
    // ".service" and silently made every systemd unit look hand-started.
    std::string cgroup = raw;
    while (!cgroup.empty() && (cgroup.back() == '\n' || cgroup.back() == '\r' ||
                               cgroup.back() == ' ' || cgroup.back() == '\t')) {
        cgroup.pop_back();
    }
    std::string unit;
    std::size_t start = 0;
    while (start <= cgroup.size()) {
        const std::size_t end = cgroup.find('/', start);
        std::string part = cgroup.substr(start, end == std::string::npos ? std::string::npos
                                                                        : end - start);
        if (part.size() > 8 && part.compare(part.size() - 8, 8, ".service") == 0) unit = part;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return unit;
}

bool unit_exists(const std::string& unit) {
    static const char* kDirs[] = {"/etc/systemd/system", "/run/systemd/system",
                                  "/usr/lib/systemd/system", "/lib/systemd/system"};
    for (const char* dir : kDirs) {
        struct stat st{};
        if (::stat((std::string(dir) + "/" + unit).c_str(), &st) == 0) return true;
    }
    return false;
}

// Runs argv with the given cwd and waits. Returns the child's exit code, or -1.
int run_and_wait(const std::vector<std::string>& argv, const std::string& cwd) {
    if (argv.empty()) return -1;
    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (!cwd.empty()) {
            if (::chdir(cwd.c_str()) != 0) ::_exit(127);
        }
        ::execvp(cargv[0], cargv.data());
        ::_exit(127);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

bool process_alive(long pid) {
    if (pid <= 0) return false;
    return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
}

bool terminate_process(long pid) {
    if (::kill(static_cast<pid_t>(pid), SIGTERM) != 0 && errno != ESRCH) return false;
    // Up to 10 s: bpb tears down sessions and the tunnel on the way out.
    for (int waited = 0; waited < 100; ++waited) {
        if (!process_alive(pid)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Still there: escalate, exactly like systemd would.
    if (::kill(static_cast<pid_t>(pid), SIGKILL) != 0 && errno != ESRCH) return false;
    for (int waited = 0; waited < 30; ++waited) {
        if (!process_alive(pid)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return !process_alive(pid);
}

void print_command(const ProcInfo& info) {
    std::printf("  pid %ld: %s", info.pid, info.argv[0].c_str());
    for (std::size_t i = 1; i < info.argv.size(); ++i) {
        std::printf(" %s", info.argv[i].c_str());
    }
    std::printf("\n");
    if (!info.cwd.empty()) std::printf("  cwd    : %s\n", info.cwd.c_str());
}

int restart_one(const ProcInfo& info) {
    print_command(info);

    const std::string unit = unit_from_cgroup(info.cgroup);
    if (!unit.empty() && unit_exists(unit)) {
        // Owned by systemd: restart the unit. Killing the pid and hoping the
        // supervisor notices would drop the unit's Restart= policy, its
        // environment and its cgroup limits; the unit is the authoritative
        // description of how this process is supposed to run.
        std::printf("  managed by systemd unit %s -> systemctl restart %s\n", unit.c_str(),
                    unit.c_str());
        const int rc = run_and_wait({"systemctl", "restart", unit}, "");
        if (rc != 0) {
            std::fprintf(stderr, "error: systemctl restart %s failed (exit %d)\n", unit.c_str(), rc);
            return 1;
        }
        return 0;
    }
    if (!unit.empty()) {
        std::printf("  cgroup names %s but that unit does not exist; treating it as a "
                    "hand-started process\n", unit.c_str());
    }

    // Hand-started: reuse the original argv verbatim. The operator's flags are
    // the only description of how this instance should run, so nothing is
    // reconstructed or normalised -- `--port 45566 --host 0.0.0.0 --data ...`
    // is replayed byte for byte.
    const std::vector<std::string> argv = info.argv;
    const std::string cwd = info.cwd;

    std::printf("  not managed by a service -> terminate and re-exec the same command\n");
    if (!terminate_process(info.pid)) {
        std::fprintf(stderr, "error: pid %ld did not exit\n", info.pid);
        return 1;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        std::fprintf(stderr, "error: fork failed: %s\n", std::strerror(errno));
        return 1;
    }
    if (pid == 0) {
        // Detach: the caller exits right after this and the new instance must
        // outlive it (it is a service in all but name).
        //
        // All three standard streams go to /dev/null, not just stdin. A child
        // that keeps the parent's stdout -- a pipe or a terminal -- makes the
        // *caller* look hung: `bpb --res | tee` would never see EOF because the
        // restarted daemon still holds the write end. Logs are not lost in the
        // usual case: a service-managed instance is restarted through systemd
        // and its journal, which is the path that matters.
        ::setsid();
        if (!cwd.empty() && ::chdir(cwd.c_str()) != 0) ::_exit(127);
        int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) ::close(devnull);
        }
        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        ::execvp(cargv[0], cargv.data());
        ::_exit(127);
    }
    // The child either becomes the new instance or dies in execvp. Check before
    // reporting success: "started pid N" for a process that is already gone is
    // worse than an error, because the operator stops looking.
    for (int waited = 0; waited < 30; ++waited) {
        if (!process_alive(pid)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!process_alive(pid)) {
        std::fprintf(stderr,
                     "error: the replacement process exited immediately; %s may have been "
                     "moved or deleted\n", argv[0].c_str());
        return 1;
    }
    std::printf("  started pid %d with the same arguments\n", static_cast<int>(pid));
    return 0;
}

#endif // !_WIN32

} // namespace

int restart_bpb(const std::string& pid_arg) {
#ifdef _WIN32
    // There is no /proc to read another process's argv from, and re-exec with
    // the original parameters is not possible without them. Say so instead of
    // guessing (the same reason --cur on Windows needs --data).
    (void)pid_arg;
    std::fprintf(stderr, "error: --res is POSIX only (it re-execs the original command line)\n");
    return 1;
#else
    std::vector<ProcInfo> targets;
    if (!pid_arg.empty()) {
        char* end = nullptr;
        const long pid = std::strtol(pid_arg.c_str(), &end, 10);
        if (end == pid_arg.c_str() || (end && *end != '\0') || pid <= 0) {
            std::fprintf(stderr, "error: --res needs a numeric pid, got '%s'\n", pid_arg.c_str());
            return 1;
        }
        ProcInfo info = read_proc(pid);
        if (info.argv.empty()) {
            std::fprintf(stderr, "error: no process with pid %ld\n", pid);
            return 1;
        }
        if (!looks_like_bpb(info.argv)) {
            std::fprintf(stderr, "error: pid %ld is not bpb (%s)\n", pid, info.argv[0].c_str());
            return 1;
        }
        targets.push_back(std::move(info));
    } else {
        targets = discover_bpb();
        if (targets.empty()) {
            std::fprintf(stderr, "error: no running bpb process found\n");
            return 1;
        }
        // discover_bpb() sorts by pid, so the first entry is the lowest one.
        if (targets.size() > 1) {
            std::printf("bpb --res: %zu bpb processes, restarting the lowest pid (%ld)\n",
                        targets.size(), targets.front().pid);
        }
        targets.resize(1);
    }
    return restart_one(targets.front());
#endif
}

} // namespace bpb::app
