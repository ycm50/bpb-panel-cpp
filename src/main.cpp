#include "app/app.h"
#include "app/cur.h"
#include "app/passwd.h"
#include "http/http.h"
#include "inbound/inbound.h"
#include "net/http_client.h"
#include "net/net.h"
#include "net/wg_outbound.h"
#include "proxy/session.h"
#include "sub/wireguard.h"
#include "tunnel/integration.h"
#include "util/crash.h"
#include "util/log.h"
#include "util/thread.h"

#include <chrono>
#include <thread>

#include <fstream>
#include "settings/store.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/ssl.h>

#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>
#endif

int main(int argc, char** argv) {
    // First thing: a heap corruption anywhere below must leave a stack behind
    // instead of a bare "double free" line in the journal.
    bpb::install_crash_handler();
    // Every proxied session runs on its own threads, and glibc gives each new
    // thread a private malloc arena: the pages a relay thread touched stay
    // resident per arena, which is where most of the per-session RSS came from.
    // Two arenas are plenty for a relay and keep the footprint flat as sessions
    // come and go. (Alpine/musl has no malloc.h; the guard keeps CI happy.)
#if defined(__linux__) && defined(__GLIBC__)
    mallopt(M_ARENA_MAX, 2);
    mallopt(M_MMAP_THRESHOLD, 256 * 1024);
#endif
    if (!bpb::net::init()) {
        std::fprintf(stderr, "network init failed\n");
        return 1;
    }

    std::string host = "0.0.0.0";
    int port = 8080;
    std::string data_dir = "./.bpbdata";
    std::string asset_dir;  // empty: use the panel assets embedded in the binary
    std::string tls_cert;
    std::string tls_key;
    std::string export_warp;
    int cli_log_level = -1;  // -1: not given, fall back to BPB_LOG
    bool cur_requested = false;
    bool passwd_requested = false;
    bool passwd_check = false;
    std::vector<std::string> passwd_args;
    bool data_given = false;
    bool port_given = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--port") {
            port = std::atoi(next("--port").c_str());
            port_given = true;
        }
        else if (a == "--host") host = next("--host");
        else if (a == "--data") {
            data_dir = next("--data");
            data_given = true;
        }
        else if (a == "--cur") cur_requested = true;
        else if (a == "--passwd") {
            // Positional arguments that follow belong to the credential:
            //   --passwd <password>            set (user = config.accEmail)
            //   --passwd <user> <password>     set with an explicit user
            //   --passwd <password> --check    verify the running panel too
            passwd_requested = true;
            while (i + 1 < argc && std::strncmp(argv[i + 1], "--", 2) != 0) {
                passwd_args.emplace_back(argv[++i]);
            }
        }
        else if (a == "--check") passwd_check = true;
        else if (!a.empty() && a[0] != '-') passwd_args.push_back(a);   // bpb --passwd <pw> --data <dir>
        else if (a == "--assets") asset_dir = next("--assets");
        else if (a == "--export-warp") export_warp = next("--export-warp");
        else if (a == "--tls-cert") tls_cert = next("--tls-cert");
        else if (a == "--tls-key") tls_key = next("--tls-key");
        else if (a == "--log" || a == "--verbose") {
            const std::string value = next("--log");
            int lvl = 0;
            if (!bpb::log::parse_level(value.c_str(), lvl)) {
                std::fprintf(stderr, "unknown log level '%s' (off|error|warn|info|debug|trace)\n",
                             value.c_str());
                return 2;
            }
            cli_log_level = lvl;
        }
        else if (a == "--fetch") {
            std::string url = next("--fetch");
            bpb::net::httpc::Response res;
            std::string err;
            bool ok = bpb::net::httpc::get(url, res, err, 15000,
                                           {{"Accept", "application/dns-json"}});
            std::printf("ok=%d status=%d err=%s len=%zu\n", ok ? 1 : 0, res.status, err.c_str(),
                        res.body.size());
            std::printf("%.600s\n", res.body.c_str());
            return ok ? 0 : 1;
        }
        else if (a == "--help" || a == "-h") {
            std::printf("bpb native\n  --host <ip>      default 0.0.0.0\n  --port <n>       default 8080\n"
                        "  --data <dir>     default ./.bpbdata (config, settings, extracted panel)\n"
                        "  --assets <dir>   override the panel assets\n"
                        "  --tls-cert <pem> --tls-key <pem>  enable HTTPS/wss\n"
                        "  --export-warp <file>             write wg0.conf for the WARP sidecar\n"
                        "  --fetch <url>    HTTPS diagnostic\n"
                        "  --cur            print the tunnel domain of the bpb instances that are\n"
                        "                   running now (all of them on Linux; with --data on Windows)\n"
                        "  --log <level>    off|error|warn|info|debug|trace (default error: silent unless\n"
                        "                   something breaks; also settable with BPB_LOG)\n");
            return 0;
        }
    }

    // --cur answers "which tunnel domain is the live process using?" and exits.
    // It must run before the store is loaded or the port is bound, so it can be
    // used on a box that already has an instance running.
    if (cur_requested)
        return bpb::app::print_current_tunnels(data_given ? data_dir : std::string(),
                                               port_given ? port : 0);
    if (passwd_requested)
        return bpb::app::passwd::run_cli(data_dir, port, passwd_args, passwd_check);

    // Resolve the log switch before anything can want to log.
    bpb::log::init(cli_log_level);

    bpb::Store store;
    std::string error;
    if (!store.load(data_dir, error)) {
        std::fprintf(stderr, "settings load failed: %s\n", error.c_str());
        return 1;
    }
    if (!store.save(error)) {
        std::fprintf(stderr, "settings save failed: %s\n", error.c_str());
        return 1;
    }

    if (!export_warp.empty()) {
        std::string conf, err;
        if (!bpb::sub::build_wireguard_conf(store.merged(), store.warps(), conf, err)) {
            std::fprintf(stderr, "export-warp failed: %s\n", err.c_str());
            return 1;
        }
        std::ofstream out(export_warp, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::fprintf(stderr, "cannot write %s\n", export_warp.c_str());
            return 1;
        }
        out << conf;
        bpb::log::info("warp config written to %s", export_warp.c_str());
        return 0;
    }

    bpb::App app(store, asset_dir);
    if (!app.load_assets(error)) {
        std::fprintf(stderr, "assets load failed: %s\n", error.c_str());
        return 1;
    }

    // Optional userspace WireGuard outbound. Disabled by default; when the
    // panel enables it we reuse the already-registered WARP account and never
    // call the registration endpoint here.
    std::string wg_error;
    if (bpb::net::start_wg_outbound(store, wg_error)) {
        bpb::log::info("wireguard outbound enabled");
    } else if (wg_error != "wireguard outbound disabled") {
        bpb::log::error("wireguard outbound not started: %s", wg_error.c_str());
    }

    // Housekeeping: a burst of sessions leaves freed pages in the allocator and
    // exited thread stacks in glibc's cache; the last session of a burst is the
    // one that ends, so trimming only on teardown never runs after the burst is
    // over. One sleepy thread keeps an idle panel at its cold-start footprint.
    // (Both effects are glibc-specific; on Windows this is dead code, so the
    // thread is only started there where it can do something.)
#if defined(__linux__) && defined(__GLIBC__)
    std::thread([] {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            bpb::util::release_free_memory();
        }
    }).detach();
#endif

    bpb::http::Server server;
    server.set_handler([&](const bpb::http::Request& req) { return app.handle(req); });

    bpb::proxy::SessionConfig session_config;
    session_config.secure_path = store.config().securePath;
    session_config.vl_uuid = store.config().vlUUID;
    session_config.proxy_ip_mode = store.config().proxyIpMode;
    session_config.proxy_ips = store.config().proxyIPs;
    server.set_ws_handler([session_config](bpb::net::socket_t fd, SSL* ssl,
                                           const bpb::http::Request& req,
                                           const std::string& accept_key) {
        // The first path segment names the inbound protocol ("/vl", "/vl?ed=..."
        // or "/vl/<anything>"). Which protocols exist depends on how this binary
        // was configured (-DBPB_INBOUNDS), so the lookup is the authority: an
        // unknown segment is refused before the upgrade, exactly like the
        // single-protocol build used to do.
        const std::string segment = bpb::inbound::path_segment(req.path);
        const bpb::inbound::Inbound* inbound = bpb::inbound::by_path(segment, session_config);
        if (!inbound) {
            bpb::inbound::reject(fd, ssl);
            return;
        }
        inbound->serve(fd, ssl, accept_key, req.path, req.header("sec-websocket-protocol"),
                       session_config);
    });

    if (!tls_cert.empty() && !tls_key.empty()) {
        if (!server.enable_tls(tls_cert, tls_key, error)) {
            std::fprintf(stderr, "tls init failed: %s\n", error.c_str());
            return 1;
        }
    }

    if (!server.listen(host, port, error)) {
        std::fprintf(stderr, "listen failed: %s\n", error.c_str());
        return 1;
    }
    bpb::log::info("bpb native listening on %s://%s:%d (secure path: /%s/, inbounds: %s)",
                   tls_cert.empty() ? "http" : "https", host.c_str(), port,
                   store.config().securePath.c_str(), bpb::inbound::id_list().c_str());

    // Optional embedded Cloudflare Tunnel client. When enabled it registers with
    // the edge and relays inbound requests back to this panel, replacing the
    // full cloudflared binary (~40 MB) with a small in-process implementation.
    {
        bool tunnel_started = false;
        std::string tunnel_error;
        if (bpb::tunnel::start_from_store(store, tunnel_started, tunnel_error)) {
            if (tunnel_started) bpb::log::info("cloudflare tunnel client started");
        } else {
            bpb::log::error("cloudflare tunnel not started: %s", tunnel_error.c_str());
        }
    }

    server.run();
    bpb::net::shutdown();
    return 0;
}
