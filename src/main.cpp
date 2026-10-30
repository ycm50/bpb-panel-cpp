#include "app/app.h"
#include "http/http.h"
#include "net/http_client.h"
#include "net/net.h"
#include "proxy/session.h"
#include "sub/wireguard.h"

#include <fstream>
#include "settings/store.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <openssl/ssl.h>

int main(int argc, char** argv) {
    if (!bpb::net::init()) {
        std::fprintf(stderr, "network init failed\n");
        return 1;
    }

    std::string host = "0.0.0.0";
    int port = 8080;
    std::string data_dir = "./data";
    std::string asset_dir;  // empty: use the panel assets embedded in the binary
    std::string tls_cert;
    std::string tls_key;
    std::string export_warp;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--port") port = std::atoi(next("--port").c_str());
        else if (a == "--host") host = next("--host");
        else if (a == "--data") data_dir = next("--data");
        else if (a == "--assets") asset_dir = next("--assets");
        else if (a == "--export-warp") export_warp = next("--export-warp");
        else if (a == "--tls-cert") tls_cert = next("--tls-cert");
        else if (a == "--tls-key") tls_key = next("--tls-key");
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
                        "  --data <dir>     default ./data\n  --assets <dir>   override the embedded panel assets\n"
                        "  --tls-cert <pem> --tls-key <pem>  enable HTTPS/wss\n"
                        "  --export-warp <file>             write wg0.conf for the WARP sidecar\n"
                        "  --fetch <url>    HTTPS diagnostic\n");
            return 0;
        }
    }

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
        std::printf("warp config written to %s\n", export_warp.c_str());
        return 0;
    }

    bpb::App app(store, asset_dir);
    if (!app.load_assets(error)) {
        std::fprintf(stderr, "assets load failed: %s\n", error.c_str());
        return 1;
    }

    bpb::http::Server server;
    server.set_handler([&](const bpb::http::Request& req) { return app.handle(req); });

    bpb::proxy::SessionConfig session_config;
    session_config.secure_path = store.config().securePath;
    session_config.vl_uuid = store.config().vlUUID;
    session_config.tr_pass = store.config().trPass;
    session_config.proxy_ip_mode = store.config().proxyIpMode;
    session_config.proxy_ips = store.config().proxyIPs;
    server.set_ws_handler([session_config](bpb::net::socket_t fd, SSL* ssl,
                                           const bpb::http::Request& req,
                                           const std::string& accept_key) {
        bpb::proxy::run_ws_session(fd, ssl, accept_key, req.path, session_config);
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
    std::printf("bpb native listening on %s://%s:%d (secure path: /%s/)\n",
                tls_cert.empty() ? "http" : "https", host.c_str(), port,
                store.config().securePath.c_str());
    std::fflush(stdout);
    server.run();
    bpb::net::shutdown();
    return 0;
}
