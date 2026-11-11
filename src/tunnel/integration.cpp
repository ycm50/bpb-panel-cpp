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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif

namespace bpb::tunnel {

namespace {

std::mutex g_mutex;
std::atomic<bool> g_running{false};
TunnelStatus g_status;
// Shared, not unique: stop() drops the global handle on the HTTP thread while
// the detached supervisor may still be unwinding inside run(). The thread keeps
// the client alive until it returns.
std::shared_ptr<TunnelClient> g_client;
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

// Defined below, next to the probe's rationale; used by the registration path
// above it, so the declaration has to come first.
bool hostname_resolves(const std::string& host, std::string& error);

// A freshly registered quick-tunnel hostname is not published in DNS the
// instant the API answers it: measured on a live box, the name the API returned
// was NXDOMAIN when probed immediately and answered A+AAAA a few minutes later.
// Probing once and declaring the name dead therefore throws away a perfectly
// good tunnel and keeps the previous (already 530) domain instead.
//
// So: retry before believing a negative answer. Anything that is not a definite
// NXDOMAIN returns on the first pass.
bool hostname_usable(const std::string& host, int attempts, int delayMs, std::string& error) {
    for (int i = 0; i < attempts; ++i) {
        if (hostname_resolves(host, error)) return true;
        // Only a definite "no such name" is worth waiting out; a probe that
        // could not ask at all is already reported as usable by the callee.
        if (error.find("NXDOMAIN") == std::string::npos) return true;
        if (i + 1 < attempts) {
            bpb::log::info("[cf-tunnel] %s does not resolve yet (%s); retrying in %d ms",
                           host.c_str(), error.c_str(), delayMs);
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }
    return false;
}

// A quick tunnel needs no account: POST an empty body and Cloudflare hands back
// a tunnel id plus the {account_tag, secret} pair the connector authenticates
// with, and a *.trycloudflare.com hostname to reach it. One registration is
// enough - the credentials are persisted and reused so waking the panel does not
// create a new tunnel (and a new hostname) every time.
// reuse_cached: keep the credentials from a previous run. Quick tunnels are
// ad-hoc objects at the edge: when the connector goes away (reboot, service
// restart, panel sleep) the edge stops routing that hostname, and reconnecting
// with the same token re-establishes a tunnel nobody can reach -- the connector
// reports "connected", the hostname answers 530, and config.json keeps a domain
// that is already dead. So a fresh process registers a fresh tunnel; the cached
// one is only a fallback when registration cannot reach the API.
bool quick_tunnel_register(const std::string& dataDir, std::string& token,
                           std::string& hostname, std::string& error, bool reuse_cached) {
    if (reuse_cached && !dataDir.empty()) {
        std::ifstream in(dataDir + "/tunnel-quick.json");
        if (in) {
            std::stringstream ss;
            ss << in.rdbuf();
            auto j = nlohmann::json::parse(ss.str(), nullptr, false);
            if (!j.is_discarded() && j.contains("token") && j["token"].is_string()) {
                const std::string cached_host = j.value("hostname", std::string());
                // A cached name is only worth reusing while it still resolves.
                // Reconnecting to a tunnel whose hostname Cloudflare has already
                // dropped produces a connector that reports "registered" while
                // the domain answers 530 -- the exact state that made an
                // installation look healthy and every client hang.
                // "not resolving right now" is not the same as "dead": a name
                // adopted a few seconds ago is still propagating. Only a name
                // that was already marked unusable on a previous run is treated
                // as dead, so a restart right after a registration still reuses
                // the tunnel instead of registering yet another one.
                if (!cached_host.empty() && j.contains("usable") &&
                    j["usable"].is_boolean() && !j["usable"].get<bool>()) {
                    std::string probe_error;
                    if (!hostname_resolves(cached_host, probe_error)) {
                        bpb::log::error(
                            "[cf-tunnel] cached quick tunnel hostname is dead (%s): %s; "
                            "registering a fresh one instead",
                            probe_error.c_str(), cached_host.c_str());
                        return false;
                    }
                }
                token = j["token"].get<std::string>();
                hostname = cached_host;
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

    // Do not persist a hostname that does not resolve. The token is still
    // usable (it names the tunnel, not the domain), so the cached copy keeps
    // recording it, but the *hostname* is left out and the caller is told the
    // registration produced an unusable name.
    std::string probe_error;
    // One quick look here (no retries) decides only what goes into the cache:
    // the caller does the patient, retrying check before adopting the name. A
    // name that is not published yet is still the one this process is about to
    // serve, so the token is always written; only the hostname is withheld so a
    // later start cannot resurrect it from the cache.
    const bool usable = hostname_resolves(hostname, probe_error);
    if (!usable) {
        bpb::log::info("[cf-tunnel] %s is not published yet (%s); cache records the token only",
                       hostname.c_str(), probe_error.c_str());
    }

    if (!dataDir.empty()) {
        // The hostname is recorded even when it does not resolve yet.
        //
        // Withholding it meant the cache was useless for the one thing it is
        // read for: 'bpb --cur' falls back to this file, so during the 1-2 minute
        // window in which a brand-new quick tunnel name is still NXDOMAIN it
        // reported no domain at all, while the process was already serving that
        // name. `usable` is stored next to it so a reader can tell "registered,
        // not yet propagated" from "confirmed".
        nlohmann::json out = {{"token", token},
                              {"hostname", hostname},
                              {"usable", usable},
                              {"updated_at", static_cast<std::int64_t>(std::time(nullptr))}};
        std::ofstream f(dataDir + "/tunnel-quick.json", std::ios::trunc);
        if (f) f << out.dump(2);
    }
    return true;
}

// ---- hostname liveness ------------------------------------------------------
// A quick-tunnel registration hands back a *.trycloudflare.com name, and that
// name is what every subscription then tells clients to dial. The API is not a
// promise that the name already resolves: an ad-hoc tunnel can come back with a
// hostname whose DNS record is not published (or has just been reclaimed), and
// adopting it writes a dead domain into config.json, settings.json and the
// subscription in one go. Observed in production: the panel served a
// subscription pointing at a name that answered NXDOMAIN, while the *previous*
// registration's name was still resolving -- and that stale name is what the
// operator ended up pasting to make it work.
//
// So probe the name before adopting it. DoH is the probe, not getaddrinfo: this
// process may have a WARP outbound in front of its own resolver, and DoH goes
// out over the same egress a client would use.
bool hostname_resolves(const std::string& host, std::string& error) {
    if (host.empty()) {
        error = "empty hostname";
        return false;
    }
    // A literal address, a loopback name, or a name the operator pointed at
    // their own DNS needs no check here -- and must not be rejected because
    // DoH cannot see an internal zone.
    if (host == "localhost" || ends_with(host, ".localhost")) return true;

    // Ask for BOTH families. A trycloudflare hostname does not always carry an
    // A record: the operator's own working domain in the incident this fixes had
    // AAAA only, and a type=A-only probe reports NXDOMAIN for it while clients
    // reach it fine over IPv6. Only "both families NXDOMAIN" means dead.
    int answered = 0;      // families that returned at least one record
    int nxdomain = 0;      // families that explicitly said NXDOMAIN
    int asked = 0;         // families whose answer we actually got to read
    for (const char* type : {"A", "AAAA"}) {
        const std::string url = "https://cloudflare-dns.com/dns-query?name=" +
                                url_encode(host) + "&type=" + type;
        net::httpc::Response res;
        std::string net_error;
        if (!net::httpc::get(url, res, net_error, 8000, {{"Accept", "application/dns-json"}}))
            continue;
        if (res.status != 200) continue;
        const auto j = nlohmann::json::parse(res.body, nullptr, false);
        if (j.is_discarded()) continue;
        ++asked;
        if (j.value("Status", 0) == 3) {
            ++nxdomain;
            continue;
        }
        // Status 0 = NOERROR. An empty answer section is not proof of anything
        // (the record may just not be published yet), so only count real data.
        if (j.contains("Answer") && j["Answer"].is_array() && !j["Answer"].empty()) ++answered;
    }
    if (answered > 0) return true;
    if (asked > 0 && nxdomain == asked) {
        error = "NXDOMAIN (A and AAAA)";
        return false;
    }
    // Never asked, or asked and got no usable answer. Fall back to the system
    // resolver before declaring anything: DoH is a different host from the
    // registration API, so a box that can register may still not be able to
    // reach cloudflare-dns.com. Only a resolver that positively says "no such
    // host" is treated as dead; anything else stays unverified.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &ai);
    if (ai) ::freeaddrinfo(ai);
    if (rc == 0) return true;
    // No #ifdef here: on glibc EAI_NONAME is an enum member, not a macro, so an
    // #ifdef guard silently compiled this whole check out and every dead name
    // came back "unverified" -- which is how a reclaimed hostname was adopted
    // again after the probe was written to prevent exactly that. POSIX requires
    // EAI_NONAME; this file is POSIX-only (Windows builds exclude src/tunnel/).
    if (rc == EAI_NONAME) {
        error = "NXDOMAIN (system resolver)";
        return false;
    }
    error = "unverified (DoH not asked: getaddrinfo rc " + std::to_string(rc) + ")";
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
    if (!t.value("enabled", false)) {
        // Tunnel off: give the published domain back. Without this the panel
        // kept handing out the hostname of a tunnel that is not running, which
        // is a dead name in front of no listener (the "no-tunnel mode is
        // unusable" report).
        release_adopted_domain(store);
        return true;
    }

    // Empty token = ad-hoc quick tunnel: register (or reuse) one and use it.
    // This is what makes the trimmed connector usable without a Cloudflare
    // account, and it is the path the panel's wake button takes.
    std::string token = t.value("token", "");
    std::string hostname;
    bool quick = false;
    if (token.empty()) {
        // Force a new registration: reusing the credentials of a tunnel that died
        // with the previous process yields a "connected" connector behind a dead
        // hostname. If registration fails (no egress yet, API hiccup) fall back to
        // whatever the last run persisted, so an offline box still has a domain.
        std::string fresh_error;
        if (!quick_tunnel_register(store.dir(), token, hostname, fresh_error, false)) {
            bpb::log::error("[cf-tunnel] quick tunnel registration failed: %s",
                            fresh_error.c_str());
            if (!quick_tunnel_register(store.dir(), token, hostname, fresh_error, true)) {
                error = fresh_error;
                return false;
            }
            bpb::log::error("[cf-tunnel] reusing the cached quick tunnel (%s); the hostname may "
                            "already be dead at the edge", hostname.c_str());
        }
        // A registration can succeed and still hand back a name that does not
        // resolve (see hostname_resolves). Adopting it writes a dead domain into
        // config.json and every subscription, so fall back to the domain the
        // process is already publishing -- that one at least answered when it
        // was adopted -- instead of replacing a working name with a broken one.
        if (!hostname.empty()) {
            std::string probe_error;
            // Retry, do not judge on the first look: a name the API just handed
            // out is regularly NXDOMAIN for a minute or two and perfectly good
            // after that (measured). 5 tries x 3 s covers most of the gap.
            //
            // A name that is STILL not resolving is adopted anyway.
            //
            // This used to be a hard gate: the fresh name was discarded and the
            // previous domain kept. That is how 'bpb --res' ended up publishing a
            // dead tunnel domain for the whole 15 s probe window -- and, when the
            // previous name had already been reclaimed by the edge, forever, until
            // the box was rebooted and a fresh registration raced past the window.
            // The connector is already serving the new name, so the previous
            // domain is the one that is certainly wrong; publishing the new one a
            // minute early is strictly better than publishing the old one forever.
            if (!hostname_usable(hostname, 5, 3000, probe_error)) {
                bpb::log::warn(
                    "[cf-tunnel] %s is not published yet (%s); adopting it anyway -- the "
                    "connector is already serving this name and the previous domain is dead",
                    hostname.c_str(), probe_error.c_str());
            }
        }
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
    g_client = std::make_shared<TunnelClient>();
    std::shared_ptr<TunnelClient> client = g_client;
    TunnelClient* raw = client.get();
    const std::uint64_t generation = ++g_generation;
    g_running.store(true);
    // Fresh attempt: never report the previous session's registration as
    // current. The ingress hostnames are kept -- they describe the tunnel, not
    // the connection.
    g_status.connected = false;
    g_status.registered = false;
    g_status.error.clear();
    started = true;

    g_thread = std::thread([raw, client, cfg, generation]() {
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
    // The served counter lives in the client's own status object, which is
    // published into g_status only at connect/ingress/registration time; reading
    // the live client keeps the panel's number honest between publishes without
    // taking the tunnel's status mutex per request.
    {
        std::shared_ptr<TunnelClient> client;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            client = g_client;
        }
        if (client) {
            const std::uint64_t served = client->requests_served();
            std::lock_guard<std::mutex> lock(g_mutex);
            if (served > g_status.requestsServed) g_status.requestsServed = served;
        }
    }
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

void release_adopted_domain(Store& store) {
    const std::string adopted = store.kv().value("tunnelAdoptedDomain", std::string());
    const std::string cur = store.config().mainDomain;
    // Only roll back a value this supervisor wrote. Anything else is the
    // operator's own choice (or a name they typed before the tunnel ever ran)
    // and must survive the tunnel being switched off.
    const bool weOwnIt = (cur == adopted) ||
                         (cur.empty() || cur == "localhost");
    if (!weOwnIt) return;
    // Where to go back to: the address the panel advertises for direct access,
    // falling back to the value the panel started with.
    std::string fallback = store.config().directHost;
    if (fallback.empty() || fallback == "localhost") {
        const std::string host = store.listen_host();
        if (!host.empty() && host != "0.0.0.0" && host != "::") fallback = host;
        else if (!adopted.empty()) fallback = "localhost";
    }
    if (fallback.empty()) fallback = "localhost";
    if (cur == fallback && adopted.empty()) return;
    store.config().mainDomain = fallback;
    store.kv().erase("tunnelAdoptedDomain");
    bpb::log::info("[cf-tunnel] mainDomain: \"%s\" -> \"%s\" (tunnel off)", cur.c_str(),
                   fallback.c_str());
    std::string saveError;
    if (!store.save(saveError))
        bpb::log::error("[cf-tunnel] could not persist mainDomain: %s", saveError.c_str());
}

void sync_ingress_domain(Store& store) {
    // The ingress configuration only describes a *running* tunnel. With the
    // tunnel switched off (or asleep) this must not run at all, otherwise the
    // hostnames cached from the previous session get adopted again the first
    // time the panel or a subscription is fetched -- which is exactly how a
    // disabled tunnel kept reappearing in every config.
    if (store.kv().contains("cfTunnel") && store.kv()["cfTunnel"].is_object() &&
        !store.kv()["cfTunnel"].value("enabled", false)) {
        release_adopted_domain(store);
        return;
    }
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

// Single entry point the panel calls after it has persisted a new
// cfTunnel.enabled value. Saving "禁用" used to only write the flag: nothing
// told the connector to stop, so the process kept dialling the edge until it
// was restarted. Kept here (not in app.cpp) so the store -> connector decision
// lives with the connector and cannot drift again.
void apply_store_state(Store& store) {
    const nlohmann::json kv = store.merged();
    bool enabled = false;
    if (kv.contains("cfTunnel") && kv["cfTunnel"].is_object())
        enabled = kv["cfTunnel"].value("enabled", false);
    if (!enabled) {
        stop();
        return;
    }
    bool started = false;
    std::string error;
    if (!start_from_store(store, started, error))
        bpb::log::error("[cf-tunnel] could not start: %s", error.c_str());
}

void stop() {
    std::lock_guard<std::mutex> lock(g_mutex);
    // stopping_ is a one-way latch: once set, every later run() on the same
    // object returns immediately, so the supervisor would spin its reconnect
    // loop forever if g_client stayed alive (and a wake could never reuse it).
    // Signal the live connection, drop our reference so the supervisor thread
    // becomes the sole owner, and let start_from_store() build a fresh client.
    if (g_client) {
        g_client->stop();   // latches stopping_ and shutdown(2)s the edge socket
        // Drop the supervisor's handle. The detached thread holds its own
        // shared_ptr, so the object stays alive until run() actually returns;
        // the next start_from_store() then builds a *fresh* client instead of
        // reusing a latched one (which would return from run() instantly and
        // spin the reconnect loop).
        g_client.reset();
    }
    // Report the tunnel as down right away. The supervisor only clears its own
    // copy once run() returns, and until then the panel kept showing a sleeping
    // tunnel as running/connected.
    g_running.store(false);
    g_status.connected = false;
    g_status.registered = false;
}

} // namespace bpb::tunnel
