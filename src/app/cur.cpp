#include "app/cur.h"

#include "net/http_client.h"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#endif

namespace bpb::app {

namespace {

struct Instance {
    long pid = 0;
    int port = 8080;
    std::string data_dir;
    std::string domain;      // tunnel hostname, file based
    std::string state;       // "connected" / "offline" / "-"
    std::string source;      // where the domain came from (quick / mainDomain / panel)
};

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Empty when the key is absent. Handles the escaped quotes our own JSON writes.
std::string json_string(const std::string& body, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    auto at = body.find(needle);
    if (at == std::string::npos) return {};
    at = body.find(':', at + needle.size());
    if (at == std::string::npos) return {};
    at = body.find('"', at);
    if (at == std::string::npos) return {};
    std::string out;
    for (std::size_t i = at + 1; i < body.size(); ++i) {
        const char c = body[i];
        if (c == '\\' && i + 1 < body.size()) {
            out.push_back(body[++i]);
            continue;
        }
        if (c == '"') break;
        out.push_back(c);
    }
    return out;
}

bool json_bool(const std::string& body, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    auto at = body.find(needle);
    if (at == std::string::npos) return false;
    at = body.find(':', at + needle.size());
    if (at == std::string::npos) return false;
    for (std::size_t i = at; i < body.size() && i < at + 16; ++i) {
        if (body.compare(i, 4, "true") == 0) return true;
        if (body.compare(i, 5, "false") == 0) return false;
    }
    return false;
}

std::string trim_slash(std::string s) {
    while (!s.empty() && s.front() == '/') s.erase(s.begin());
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

// Fills domain/state for one instance: files first (they survive a dead panel),
// then ask the running panel, which is the only place that knows whether the
// tunnel is actually connected.
void describe(Instance& inst) {
    const std::string config = read_file(inst.data_dir + "/config.json");
    const std::string secure = trim_slash(json_string(config, "securePath"));
    const std::string main_domain = json_string(config, "mainDomain");

    const std::string quick = read_file(inst.data_dir + "/tunnel-quick.json");
    const std::string quick_host = json_string(quick, "hostname");
    if (!quick_host.empty()) {
        inst.domain = quick_host;
        inst.source = "quick tunnel";
    } else if (!main_domain.empty() && main_domain != "localhost") {
        inst.domain = main_domain;
        inst.source = "mainDomain";
    }

    std::string url = "http://127.0.0.1:" + std::to_string(inst.port) + "/";
    if (!secure.empty()) url += secure + "/";
    url += "panel/tunnel-status";
    net::httpc::Response res;
    std::string error;

    // The command line has full access, so it just says who it is. No token to
    // read, no login round trip: a header a browser cannot send on a navigation.
    const bpb::net::httpc::Headers headers = {{"X-BPB-CLI", "1"}};
    const bool ok = net::httpc::get(url, res, error, 2000, headers);
    if (ok && res.status == 200) {
        inst.source = "panel";
        const std::string host = json_string(res.body, "hostname");
        if (!host.empty()) inst.domain = host;
        if (json_bool(res.body, "connected")) {
            inst.state = "connected";
        } else if (json_bool(res.body, "running")) {
            inst.state = "running, not connected";
        } else {
            inst.state = "offline";
        }
    } else if (res.status == 401 || res.status == 403) {
        // The panel is password-protected (the normal state on a real install),
        // so tunnel-status refuses an anonymous read. That is not "unreachable":
        // the domain from the data directory is still the live one.
        inst.state = inst.domain.empty() ? "locked (login required)"
                                         : "locked (login required, from files)";
    } else if (!inst.domain.empty()) {
        inst.state = "unreachable (from files)";
    } else {
        inst.state = "no tunnel";
    }
}

#ifndef _WIN32
// Every bpb process on the box: /proc carries the command line, so the port and
// the data directory of a live instance are exact rather than guessed.
std::vector<Instance> discover_posix() {
    std::vector<Instance> found;
    DIR* dir = ::opendir("/proc");
    if (!dir) return found;
    const long self = static_cast<long>(::getpid());
    while (dirent* ent = ::readdir(dir)) {
        const char* name = ent->d_name;
        if (name[0] < '0' || name[0] > '9') continue;
        const long pid = std::strtol(name, nullptr, 10);
        if (pid == self) continue;
        const std::string base = std::string("/proc/") + name + "/";
        const std::string raw = read_file(base + "cmdline");
        if (raw.empty()) continue;

        std::vector<std::string> args;
        std::string cur;
        for (char c : raw) {
            if (c == '\0') {
                if (!cur.empty()) args.push_back(cur);
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) args.push_back(cur);
        if (args.empty()) continue;

        std::string exe = args[0];
        const auto slash = exe.find_last_of('/');
        if (slash != std::string::npos) exe = exe.substr(slash + 1);
        if (exe.find("bpb") == std::string::npos) continue;

        Instance inst;
        inst.pid = pid;
        bool has_port = false;
        bool has_data = false;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--port" && i + 1 < args.size()) {
                inst.port = std::atoi(args[++i].c_str());
                has_port = true;
            } else if (args[i] == "--data" && i + 1 < args.size()) {
                inst.data_dir = args[++i];
                has_data = true;
            }
        }
        if (!has_port) inst.port = 8080;   // main.cpp's default
        if (!has_data) inst.data_dir = "./.bpbdata";
        if (inst.data_dir.empty() || inst.data_dir[0] != '/') {
            char link[4096];
            const std::string cwd_link = base + "cwd";
            const ssize_t n = ::readlink(cwd_link.c_str(), link, sizeof(link) - 1);
            if (n > 0) {
                link[n] = '\0';
                inst.data_dir = std::string(link) + "/" + inst.data_dir;
            }
        }
        found.push_back(std::move(inst));
    }
    ::closedir(dir);
    return found;
}
#else
// Windows builds carry no tunnel (see platform/tunnel_stub.cpp), and there is no
// portable way to read another process's command line, so discovery is limited
// to the pids we can name. --data is the supported way to inspect one instance.
std::vector<Instance> discover_windows() {
    std::vector<Instance> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return found;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const DWORD self = GetCurrentProcessId();
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ProcessID == self) continue;
            std::wstring wide(entry.szExeFile);
            std::string exe(wide.begin(), wide.end());
            if (exe.find("bpb") == std::string::npos) continue;
            Instance inst;
            inst.pid = static_cast<long>(entry.th32ProcessID);
            found.push_back(std::move(inst));
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}
#endif

void print_row(const Instance& inst) {
    std::printf("%-8ld %-6d %-46s %-22s", inst.pid, inst.port,
                inst.domain.empty() ? "(no tunnel)" : inst.domain.c_str(),
                inst.state.c_str());
    if (!inst.source.empty()) std::printf(" [%s]", inst.source.c_str());
    if (!inst.data_dir.empty()) std::printf(" data=%s", inst.data_dir.c_str());
    std::printf("\n");
}

} // namespace

int print_current_tunnels(const std::string& data_override, int port_override) {
    std::vector<Instance> instances;
    if (!data_override.empty()) {
        // A data directory with no config.json is not an instance: report it
        // instead of printing an empty row that looks like a healthy one.
        if (read_file(data_override + "/config.json").empty()) {
            std::fprintf(stderr, "no bpb instance at %s (config.json missing)\n",
                         data_override.c_str());
            return 1;
        }
        Instance inst;
        inst.pid = 0;
        inst.data_dir = data_override;
        if (port_override > 0) inst.port = port_override;
        instances.push_back(std::move(inst));
    } else {
#ifdef _WIN32
        instances = discover_windows();
        if (instances.empty()) {
            std::printf("no running bpb.exe found\n");
            return 1;
        }
        std::printf("Windows builds carry no built-in tunnel; pass --cur --data <dir> to read "
                    "a local instance.\n");
        for (auto& inst : instances) {
            std::printf("%-8ld (command line unavailable on Windows)\n", inst.pid);
        }
        return 0;
#else
        instances = discover_posix();
        if (instances.empty()) {
            std::printf("no running bpb process found\n");
            return 1;
        }
#endif
    }

    std::printf("%-8s %-6s %-46s %-22s\n", "pid", "port", "tunnel domain", "state");
    for (auto& inst : instances) {
        describe(inst);
        print_row(inst);
    }
    return 0;
}

} // namespace bpb::app
