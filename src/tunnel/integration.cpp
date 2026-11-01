#include "tunnel/integration.h"
#include "util/log.h"

#include "net/http_client.h"
#include "settings/store.h"
#include "tunnel/client.h"
#include "tunnel/ingress.h"
#include "util/util.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

namespace bpb::tunnel {

namespace {

std::mutex g_mutex;
std::atomic<bool> g_running{false};
TunnelStatus g_status;
std::unique_ptr<TunnelClient> g_client;
std::thread g_thread;
// Public hostname of this tunnel. Set by the quick-tunnel API for an ad-hoc
// tunnel, or from the edge's ingress configuration for a named one.
std::string g_hostname;
bool g_quick = false;
// Ingress hostnames pushed by the edge for a named tunnel. This is the only
// source for them: the connector token has no hostname, and the REST API that
// would return one needs an account API token the panel does not have.
std::vector<std::string> g_ingress;
std::string g_ingress_used;   // mainDomain value this supervisor last adopted
// Monotonic id of the current supervisor run. A sleeping tunnel's thread can
// still be unwinding when wake() starts a new one, and without this its exit
// would publish g_running=false over the fresh connection (observed: status
// reported connected=true with running=false right after wake).
std::uint64_t g_generation = 0;

// A quick tunnel needs no account: POST an empty body and Cloudflare hands back
// a tunnel id plus the {account_tag, secret} pair the connector authenticates
// with, and a *.trycloudflare.com hostname to reach it. One registration is
// enough - the credentials are persisted and reused so waking the panel does not
// create a new tunnel (and a new hostname) every time.
bool quick_tunnel_register(const std::string& dataDir, std::string& token,
                           std::string& hostname, std::string& error) {
    if (!dataDir.empty()) {
        std::ifstream in(dataDir + "/tunnel-quick.json");
        if (in) {
            std::stringstream ss;
            ss << in.rdbuf();
            auto j = nlohmann::json::parse(ss.str(), nullptr, false);
            if (!j.is_discarded() && j.contains("token") && j["token"].is_string()) {
                token = j["token"].get<std::string>();
                hostname = j.value("hostname", std::string());
                if (!token.empty()) return true;
            }
        }
    }

    net::httpc::Response res;
    if (!net::httpc::post("https://api.trycloudflare.com/tunnel", "{}", res, error, 20000,
                          {{"User-Agent", "cloudflared/2026.10.7"},
                           {"Content-Type", "application/json"}})) {
        error = "quick tunnel registration failed: " + error;
        return false;
    }
    if (res.status != 200) {
        error = "quick tunnel registration returned HTTP " + std::to_string(res.status);
        return false;
    }
    auto j = nlohmann::json::parse(res.body, nullptr, false);
    if (j.is_discarded() || !j.contains("result") || !j["result"].is_object()) {
        error = "quick tunnel registration returned unexpected JSON";
        return false;
    }
    const auto& r = j["result"];
    const std::string id = r.value("id", std::string());
    const std::string account = r.value("account_tag", std::string());
    const std::string secret = r.value("secret", std::string());
    hostname = r.value("hostname", std::string());
    if (id.empty() || account.empty() || secret.empty()) {
        error = "quick tunnel credentials incomplete";
        return false;
    }
    // The connector token is just this triple, base64 encoded - the same shape a
    // user pastes from the Zero Trust dashboard.
    nlohmann::json cred = {{"a", account}, {"t", id}, {"s", secret}};
    token = base64_encode(cred.dump());

    if (!dataDir.empty()) {
        nlohmann::json out = {{"token", token}, {"hostname", hostname}};
        std::ofstream f(dataDir + "/tunnel-quick.json", std::ios::trunc);
        if (f) f << out.dump(2);
    }
    return true;
}

std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

} // namespace

bool start_from_store(Store& store, bool& started, std::string& error) {
    started = false;
    const nlohmann::json kv = store.merged();
    if (!kv.contains("cfTunnel") || !kv["cfTunnel"].is_object()) return true;
    const auto& t = kv["cfTunnel"];
    if (!t.value("enabled", false)) return true;

    // Empty token = ad-hoc quick tunnel: register (or reuse) one and use it.
    // This is what makes the trimmed connector usable without a Cloudflare
    // account, and it is the path the panel's wake button takes.
    std::string token = t.value("token", "");
    std::string hostname;
    bool quick = false;
    if (token.empty()) {
        if (!quick_tunnel_register(store.dir(), token, hostname, error)) return false;
        quick = true;
        // The public hostname is reported by install.sh, not on every start:
        // see log.h -- bpb is silent by default unless asked.
        bpb::log::info("[cf-tunnel] quick tunnel registered: https://%s", hostname.c_str());
    }
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        // A named tunnel learns its hostname from the edge's ingress push, which
        // has not arrived yet at this point. Overwriting with an empty value here
        // made a re-wake look like "no public URL" until the next poll, and lost
        // the hostname the previous session had already learned.
        if (quick || !hostname.empty()) g_hostname = hostname;
        g_quick = quick;
    }

    // Keep the published domain in step with the tunnel.
    //
    // The subscription generators read Config::mainDomain, a static field loaded
    // from config.json at startup. Nothing tied it to the tunnel, so after the
    // named tunnel died the panel kept handing out configs pointing at
    // rd.5704524.xyz and every client was dead even though the connector was
    // healthy. An ad-hoc quick tunnel IS the public entrance, so adopt its
    // hostname; the override is logged with the previous value.
    if (quick && !hostname.empty()) {
        auto& kvRef = store.kv();
        const std::string cur = store.config().mainDomain;
        bool dirty = false;
        if (cur != hostname) {
            store.config().mainDomain = hostname;
            dirty = true;
            bpb::log::info("[cf-tunnel] mainDomain: \"%s\" -> \"%s\"", cur.c_str(),
                           hostname.c_str());
        }
        if (kvRef.value("tunnelAdoptedDomain", std::string()) != hostname) {
            kvRef["tunnelAdoptedDomain"] = hostname;
            dirty = true;
        }
        if (dirty) {
            std::string saveError;
            if (!store.save(saveError))
                bpb::log::error("[cf-tunnel] could not persist mainDomain: %s",
                                saveError.c_str());
        }
    }

    tunnel::TunnelConfig cfg;
    if (!TunnelClient::parse_token(token, cfg, error)) return false;
    cfg.edgeHost = t.value("edgeHost", cfg.edgeHost);
    cfg.edgePort = static_cast<std::uint16_t>(t.value("edgePort", static_cast<int>(cfg.edgePort)));
    cfg.originHost = t.value("originHost", cfg.originHost);
    cfg.originPort = static_cast<std::uint16_t>(t.value("originPort", static_cast<int>(cfg.originPort)));

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_running.load()) {
        started = true;
        return true;
    }
    g_client = std::make_unique<TunnelClient>();
    TunnelClient* raw = g_client.get();
    const std::uint64_t generation = ++g_generation;
    g_running.store(true);
    // Fresh attempt: never report the previous session's registration as
    // current. The ingress hostnames are kept -- they describe the tunnel, not
    // the connection.
    g_status.connected = false;
    g_status.registered = false;
    g_status.error.clear();
    started = true;

    g_thread = std::thread([raw, cfg, generation]() {
        auto log = [](const std::string& line) {
            std::fprintf(stderr, "[cf-tunnel] %s\n", line.c_str());
        };
        // The edge owns the public hostname: for a named tunnel the only place
        // it is written down is the ingress configuration pushed on the control
        // stream. Only record it here -- the store is owned by the HTTP thread,
        // so the adoption happens there (see sync_ingress_domain) instead of
        // mutating JSON from this thread.
        auto on_status = [generation](const tunnel::TunnelStatus& st) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (generation != g_generation) return;
            // Live view: the panel polls status while run() is still going, and
            // the old code only copied the status after the run ended, so a
            // healthy tunnel reported connected=false forever.
            g_status = st;
            if (!st.hostnames.empty()) g_ingress = st.hostnames;
            // The hostnames describe the tunnel, not the connection, so they
            // survive a reconnect: run() starts each attempt with an empty
            // status and would otherwise report "unknown" until the edge
            // resends the ingress configuration.
            g_status.hostnames = g_ingress;
            const std::string picked = tunnel::first_usable_hostname(g_ingress);
            if (!g_quick && !picked.empty()) g_hostname = picked;
        };
        // Supervisor: a tunnel that loses its edge connection must re-register,
        // otherwise the panel answers 530 for every request until the process is
        // restarted (observed in production). Back off exponentially so a
        // Cloudflare-side outage does not turn into a reconnect storm, and reset
        // the delay as soon as a run actually registers.
        int delayMs = 1000;
        for (;;) {
            TunnelStatus local;
            raw->run(cfg, local, log, on_status);
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                // Only this generation may publish its own teardown. After a
                // sleep+wake the old thread can still be returning from run()
                // here, and overwriting the fresh connection's state is exactly
                // what made status report connected=true with running=false.
                if (generation != g_generation) break;
                g_status = local;
                g_status.connected = false;
                g_status.hostnames = g_ingress;
            }
            if (raw->stopping()) break;
            const std::string backoff = "reconnecting in " + std::to_string(delayMs / 1000) + "s";
            if (bpb::log::enabled(bpb::log::kWarn)) log("[tunnel] " + backoff);
            // Sleep in short slices so stop() takes effect promptly.
            for (int waited = 0; waited < delayMs && !raw->stopping(); waited += 200) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            if (raw->stopping()) break;
            delayMs = local.registered ? 1000 : std::min(delayMs * 2, 30000);
        }
        std::lock_guard<std::mutex> lk(g_mutex);
        // A stale thread must not clear the flag of the run that replaced it.
        if (generation == g_generation) g_running.store(false);
    });
    g_thread.detach();
    return true;
}

std::string status_json() {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::ostringstream os;
    os << "{\"running\":" << (g_running.load() ? "true" : "false")
       << ",\"connected\":" << (g_status.connected ? "true" : "false")
       << ",\"registered\":" << (g_status.registered ? "true" : "false")
       << ",\"uuid\":\"" << json_escape(g_status.uuid) << "\""
       << ",\"location\":\"" << json_escape(g_status.location) << "\""
       << ",\"requests\":" << g_status.requestsServed
       << ",\"quick\":" << (g_quick ? "true" : "false")
       << ",\"hostname\":\"" << json_escape(g_hostname) << "\""
       << ",\"url\":\"" << json_escape(g_hostname.empty() ? std::string() : "https://" + g_hostname) << "\""
       << ",\"hostnames\":[";
    for (std::size_t i = 0; i < g_ingress.size(); ++i) {
        if (i) os << ",";
        os << "\"" << json_escape(g_ingress[i]) << "\"";
    }
    os << "]"
       << ",\"mainDomain\":\"" << json_escape(g_hostname) << "\""
       << ",\"error\":\"" << json_escape(g_status.error) << "\"}";
    return os.str();
}

void sync_ingress_domain(Store& store) {
    std::string picked;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_ingress.empty()) return;
        picked = first_usable_hostname(g_ingress);
        if (picked.empty()) return;
        if (g_ingress_used == picked && store.config().mainDomain == picked) return;
    }
    const std::string cur = store.config().mainDomain;
    // Only take the ingress hostname over when the published domain is unset,
    // still the factory default, or was itself adopted from a previous ingress
    // update. A domain the user typed by hand wins: they may be pointing the
    // subscriptions somewhere the connector's ingress does not mention.
    const std::string adopted = store.kv().value("tunnelAdoptedDomain", std::string());
    const bool weOwnIt = (cur.empty() || cur == "localhost" || cur == adopted);
    {
        // Remember the hostname either way, so a later poll does not redo this
        // work; adoption itself stays a no-op while the user's value stands.
        std::lock_guard<std::mutex> lock(g_mutex);
        g_ingress_used = picked;
    }
    if (!weOwnIt) return;
    store.config().mainDomain = picked;
    store.kv()["tunnelAdoptedDomain"] = picked;
    bpb::log::info("[cf-tunnel] mainDomain: \"%s\" -> \"%s\" (ingress)", cur.c_str(),
                   picked.c_str());
    std::string saveError;
    if (!store.save(saveError))
        bpb::log::error("[cf-tunnel] could not persist mainDomain: %s", saveError.c_str());
}

void stop() {
    std::lock_guard<std::mutex> lock(g_mutex);
    // The client is owned by the supervisor thread; only the flag is touched
    // here, so nothing can be freed underneath a running run().
    if (g_client) g_client->stop();
    // Report the tunnel as down right away. The supervisor only clears its own
    // copy once run() returns, and until then the panel kept showing a sleeping
    // tunnel as running/connected.
    g_running.store(false);
    g_status.connected = false;
    g_status.registered = false;
}

} // namespace bpb::tunnel
