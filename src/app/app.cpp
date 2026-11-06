#include "app/app.h"
#include "app/passwd.h"
#include "app/qrcode.h"
#include "inbound/inbound.h"
#include "assets_gen.h"
#include "crypto/crypto.h"
#include "net/http_client.h"
#include "net/wg_outbound.h"
#include "net/selfsigned.h"
#include "sub/clash.h"
#include "sub/raw.h"
#include "util/log.h"
#include "sub/singbox.h"
#include "sub/warp.h"
#include "sub/wireguard.h"
#include "sub/xray.h"
#include "tunnel/integration.h"
#include "util/util.h"

#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace bpb {

static std::string read_text(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string join_lines(const std::vector<std::string>& lines) {
    std::string out;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i) out += "\n";
        out += lines[i];
    }
    return out;
}

static http::Response json_ok(const nlohmann::json& body) {
    nlohmann::json j;
    j["success"] = true;
    j["status"] = 200;
    j["message"] = "";
    j["body"] = body;
    return http::Response::json(200, j.dump());
}

static http::Response json_err(int status, const std::string& message) {
    nlohmann::json j;
    j["success"] = false;
    j["status"] = status;
    j["message"] = message;
    j["body"] = nullptr;
    return http::Response::json(status, j.dump());
}

App::App(Store& store, std::string asset_dir) : store_(store), asset_dir_(std::move(asset_dir)) {}

bool App::write_file(const std::string& path, const std::string& data) {
    std::error_code ec;
    auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, ec);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(f);
}

// Extracts the panel into <data>/assets on first run.
//
// The pages are compiled into the binary so a lone executable still works, but
// keeping them *only* in there meant every CSS or icon tweak needed a rebuild
// and a redeploy. Writing them out once gives the same single-file start while
// making the deployed copy editable; existing files are never overwritten, so
// local edits survive upgrades.
bool App::extract_assets(const std::string& dir, std::string& error) {
    static const char* kPages[] = {"panel", "login", "error"};
    bool wroteAny = false;
    for (const char* page : kPages) {
        const std::string path = dir + "/" + page + "/index.html";
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) continue;
        std::size_t len = 0;
        const char* data = assets::page(page, len);
        if (!data || len == 0) continue;
        if (!write_file(path, std::string(data, len))) {
            // A read-only data directory must not be fatal: the embedded copy
            // is still served, only local editing is unavailable.
            bpb::log::warn("[assets] could not write %s, serving the embedded copy",
                           path.c_str());
            continue;
        }
        wroteAny = true;
    }
    if (wroteAny) bpb::log::info("[assets] panel extracted to %s", dir.c_str());

    const std::string iconPath = dir + "/favicon.ico";
    std::error_code ec;
    if (!std::filesystem::exists(iconPath, ec)) {
        std::size_t len = 0;
        const char* data = assets::icon(len);
        if (data && len) write_file(iconPath, std::string(data, len));
    }
    (void)error;
    return true;
}

// Native build has no Cloudflare account/analytics integration: hide
// those controls with CSS only, so the browser-side script keeps running
// against the elements it expects to exist.
static const char* kNativeHideCss =
    "<style>"
    ".section:has(#total-usage){display:none!important;}"
    ".dashboard-action:has(#updatePanel){display:none!important;}"
    ".dashboard-action:has(#deletePanel){display:none!important;}"
    "</style>";

std::string App::page(const char* name, std::string& error) const {
    const std::string dir = asset_dir_.empty() ? store_.dir() + "/assets" : asset_dir_;
    std::string text = read_text(dir + "/" + name + "/index.html");
    if (!text.empty()) return text;
    // Embedded fallback keeps a lone binary working when the data directory is
    // read-only or the file was deleted.
    std::size_t len = 0;
    const char* data = assets::page(name, len);
    if (data && len) return std::string(data, len);
    error = std::string("no ") + name + " page available";
    return std::string();
}

std::string App::icon_b64() const {
    const std::string dir = asset_dir_.empty() ? store_.dir() + "/assets" : asset_dir_;
    std::string icon = read_text(dir + "/favicon.ico");
    if (icon.empty()) {
        std::size_t len = 0;
        const char* data = assets::icon(len);
        if (data) icon.assign(data, len);
    }
    return base64_encode(icon);
}

std::string App::render_page(const char* name, bool is_panel, std::string& error) const {
    std::string html = page(name, error);
    if (html.empty()) return html;
    html = replace_all(std::move(html), "__VERSION__", version_);
    html = replace_all(std::move(html), "__ICON__", icon_b64());
    if (is_panel) html += kNativeHideCss;
    return html;
}

bool App::load_assets(std::string& error) {
    // Default location: <data>/assets, written out once on first run so the
    // panel can be edited in place. --assets points somewhere else and skips
    // the extraction.
    if (asset_dir_.empty()) {
        const std::string dir = store_.dir() + "/assets";
        extract_assets(dir, error);
    }
    // Nothing is cached: every request re-reads the file (see page()). Startup
    // only checks that at least the panel can be produced, so a broken install
    // still fails loudly instead of serving 404s.
    std::string check_error;
    if (render_page("panel", true, check_error).empty() ||
        render_page("login", false, check_error).empty()) {
        error = check_error.empty() ? "no panel assets available" : check_error;
        return false;
    }
    return true;
}

std::string App::cookie(const http::Request& req, const std::string& name) const {
    std::string raw = req.header("cookie");
    std::string needle = name + "=";
    std::size_t pos = 0;
    while ((pos = raw.find(needle, pos)) != std::string::npos) {
        bool boundary = (pos == 0) || (raw[pos - 1] == ';') || (raw[pos - 1] == ' ');
        if (boundary) {
            std::size_t start = pos + needle.size();
            std::size_t end = raw.find(';', start);
            std::string value = raw.substr(start, end == std::string::npos ? std::string::npos : end - start);
            return trim(value);
        }
        pos += needle.size();
    }
    return "";
}

namespace {

// The command line runs on the box as the operator: it gets full access, with
// no password and no token to manage.
//
// What it must NOT share is the old rule of "anything that arrives on loopback
// is the operator". Two things reach 127.0.0.1 that are not the CLI: a browser on
// the box, and -- the one that actually mattered -- this process's own outgoing
// tunnel, whose origin connections come from 127.0.0.1 as well. A browser cannot
// forge the distinction: a top-level navigation cannot carry a custom request
// header at all, and a cross-origin page that adds one triggers a CORS preflight
// this server never answers.
bool is_loopback(const bpb::http::Request& req) {
    const std::string& p = req.peer;
    if (p.empty()) return false;
    return p == "127.0.0.1" || p == "::1" || p == "::ffff:127.0.0.1";
}

bool is_cli_request(const bpb::http::Request& req) {
    if (!is_loopback(req)) return false;
    return !req.header("x-bpb-cli").empty();
}

// Session lifetime for a browser. Short on purpose: the cookie is only a
// convenience for a page that is already open, not a long-lived credential.
constexpr std::int64_t kSessionSeconds = 10 * 60;

} // namespace

bool App::authenticated(const http::Request& req) const {
    // The command line has full access, unconditionally and with no secret to
    // manage: it announces itself with a header only it sends.
    if (is_cli_request(req)) return true;
    std::string token = cookie(req, "jwtToken");
    if (token.empty()) return false;
    std::string payload;
    if (!crypto::jwt_verify_hs256(token, store_.secret(), payload)) return false;
    try {
        auto j = nlohmann::json::parse(payload);
        if (!j.contains("exp")) return false;
        std::int64_t exp = j["exp"].get<std::int64_t>();
        std::time_t now = std::time(nullptr);
        return static_cast<std::int64_t>(now) < exp;
    } catch (...) {
        return false;
    }
}

http::Response App::not_supported(const std::string& what) {
    return json_err(501, what + " 在原生版本中不可用。");
}

http::Response App::login(const http::Request& req) {
    if (req.method != "POST") return json_err(405, "请求方法不允许。");
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(req.body);
    } catch (...) {
        return json_err(400, "请求体不是合法 JSON。");
    }
    std::string username = data.value("username", "");
    std::string password = data.value("password", "");
    username = to_lower(username);

    // The credential lives in <data>/passwd as a salted SHA-256 (see
    // app/passwd.h). settings.json only remains as the legacy fallback: an
    // install that predates the file still logs in, and the first successful
    // login migrates it so nothing keeps a plaintext password around.
    // The file is authoritative and is re-read on every attempt: a password
    // changed while the panel is running must take effect immediately.
    bool ok = false;
    app::passwd::Entry entry;
    if (app::passwd::load(store_.dir(), entry)) {
        ok = app::passwd::verify(store_.dir(), username, password);
    } else {
        // Legacy value from settings.json; migrate it to <data>/passwd below.
        ok = (username == to_lower(store_.config().accEmail) && password == store_.pwd());
        if (ok && !store_.pwd().empty()) {
            std::string migrate_error;
            app::passwd::save(store_.dir(), username, password, migrate_error);
            if (!migrate_error.empty())
                bpb::log::error("could not migrate the panel password: %s", migrate_error.c_str());
        }
    }
    if (!ok) return json_err(401, "用户名或密码错误。");
    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    nlohmann::json payload;
    payload["id"] = store_.config().accID;
    payload["iat"] = now;
    payload["exp"] = now + kSessionSeconds;
    std::string token = crypto::jwt_sign_hs256(payload.dump(), store_.secret());
    http::Response res = json_ok(nullptr);
    // Session cookie, not a durable one: no Max-Age/Expires means the browser
    // drops it when it closes, and the signed 'exp' above caps it at ten
    // minutes even while the tab stays open.
    res.set("Set-Cookie",
            "jwtToken=" + token + "; Path=/; HttpOnly; SameSite=Strict");
    return res;
}

http::Response App::logout() {
    http::Response res = json_ok(nullptr);
    res.set("Set-Cookie", "jwtToken=; Path=/; SameSite=Strict; Max-Age=0");
    return res;
}

http::Response App::panel_settings() {
    nlohmann::json body;
    body["proxySettings"] = store_.merged();
    body["subscriptions"] = nlohmann::json::parse(R"({
      "normal": {"label":"Normal","categories":[
        {"core":"xray","clients":["v2rayNG","MahsaNG","Streisand"]},
        {"core":"sing-box","clients":["sing-box","husi"]},
        {"core":"clash","clients":["Clash Meta","Clash Verge","FlClash","Stash"]}]},
      "fragment": {"label":"Fragment","categories":[
        {"core":"xray","clients":["v2rayNG","MahsaNG","Streisand"]},
        {"core":"sing-box","clients":["sing-box","husi"]}]},
      "raw": {"label":"Raw","categories":[
        {"core":"xray","clients":["v2rayNG","MahsaNG","Shadowrocket","Streisand","PassWall"]},
        {"core":"sing-box","clients":["husi","NekoBox","Hiddify","Karing"]}]},
      "warp": {"label":"Warp","categories":[
        {"core":"xray","clients":["v2rayNG","Streisand"]},
        {"core":"sing-box","clients":["sing-box","husi"]},
        {"core":"clash","clients":["Clash Meta","Clash Verge","FlClash","Stash"]},
        {"core":"wireguard","clients":["Wireguard"]}]},
      "warp-pro": {"label":"Warp Pro","categories":[
        {"core":"xray","clients":["v2rayNG","Streisand"]},
        {"core":"xray-knocker","clients":["MahsaNG","v2rayN-PRO"]},
        {"core":"clash","clients":["Clash Meta","Clash Verge","FlClash","Stash"]},
        {"core":"amnezia","clients":["Amnezia","WG Tunnel"]}]}
    })");
    body["clients"] = nlohmann::json::parse(R"([
      {"name":"v2rayNG","minVer":"2.2.3","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tLzJkdXN0L3YycmF5TkcvcmVsZWFzZXMvbGF0ZXN0"},
      {"name":"v2rayN","minVer":"7.22.5","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tLzJkdXN0L3YycmF5Ti9yZWxlYXNlcy9sYXRlc3Q="},
      {"name":"MahsaNG","minVer":"17","source":"Google Play","b64Url":"aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5NYWhzYU5ldC5NYWhzYU5HJmhsPWVu"},
      {"name":"Streisand","minVer":"1.6.71","source":"App Store","b64Url":"aHR0cHM6Ly9hcHBzLmFwcGxlLmNvbS91cy9hcHAvc3RyZWlzYW5kL2lkNjQ1MDUzNDA2NA=="},
      {"name":"sing-box","minVer":"1.12.0","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tL1NhZ2VyTmV0L3NpbmctYm94L3JlbGVhc2VzL2xhdGVzdA=="},
      {"name":"husi","minVer":"1.3.2","source":"Codeberg","b64Url":"aHR0cHM6Ly9jb2RlYmVyZy5vcmcveGNoYWNoYTIwLXBvbHkxMzA1L2h1c2kvcmVsZWFzZXMvbGF0ZXN0"},
      {"name":"NekoBox","minVer":"1.3.2","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tL01hdHN1cmlkYXlvL05la29Cb3hGb3JBbmRyb2lkL3JlbGVhc2VzL2xhdGVzdA=="},
      {"name":"Clash Meta","minVer":"2.11.31","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tL01ldGFDdWJlWC9DbGFzaE1ldGFGb3JBbmRyb2lkL3JlbGVhc2VzL2xhdGVzdA=="},
      {"name":"Clash verge rev","minVer":"2.5.1","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tL2NsYXNoLXZlcmdlLXJldi9jbGFzaC12ZXJnZS1yZXYvcmVsZWFzZXMvbGF0ZXN0"},
      {"name":"FlClash","minVer":"0.8.94","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tL2NoZW4wODIwOS9GbENsYXNoL3JlbGVhc2VzL2xhdGVzdA=="},
      {"name":"Stash","minVer":"3.4.1","source":"App Store","b64Url":"aHR0cHM6Ly9hcHBzLmFwcGxlLmNvbS91cy9hcHAvc3Rhc2gtcnVsZS1iYXNlZC1wcm94eS9pZDE1OTYwNjMzNDk="},
      {"name":"Amnezia","minVer":"4.8.21.0","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tL2FtbmV6aWEtdnBuL2FtbmV6aWEtY2xpZW50L3JlbGVhc2VzL2xhdGVzdA=="},
      {"name":"Wireguard","minVer":"Stable","source":"Official Website","b64Url":"aHR0cHM6Ly93d3cud2lyZWd1YXJkLmNvbS9pbnN0YWxsLw=="},
      {"name":"WG Tunnel","minVer":"5.1.0","source":"Github","b64Url":"aHR0cHM6Ly9naXRodWIuY29tL3dndHVubmVsL2FuZHJvaWQvcmVsZWFzZXMvbGF0ZXN0"}
    ])");
    // Facts the panel cannot infer from a settings blob: whether this listener
    // terminates TLS (it only does with --tls-cert/--tls-key), which port it
    // bound, and which address it advertises for direct (no-tunnel) access.
    // The panel uses these to decide which port list and which security mode it
    // may offer, instead of guessing from a hard-coded port whitelist.
    body["runtime"] = {{"listenPort", store_.listen_port()},
                       {"listenHost", store_.listen_host()},
                       {"tls", store_.listen_tls()},
                       {"accessMode", store_.merged().value("accessMode", std::string("direct"))},
                       {"directHost", store_.merged().value("directHost", std::string())},
                       {"directPort", store_.merged().value("directPort", 0)}};
    body["isPassSet"] = store_.has_pwd();
    // 这个二进制真正编进来的入栈协议。面板据此只显示这些；显示没编进来的协议
    // 只会让用户勾出一个连不上的订阅。
    body["inbounds"] = nlohmann::json::array();
    for (const inbound::Inbound* in : inbound::all()) {
        // A credential-derived path (VMess "<uuid>-vm") has no constant, so the
        // panel is told the shape instead of a null pointer.
        body["inbounds"].push_back({{"id", in->id},
                                    {"label", in->label},
                                    {"path", in->path ? in->path : "<uuid>-vm"}});
    }
    return json_ok(body);
}

// The panel's "外部原始配置" section writes the data-directory files verbatim
// instead of pretending to merge them into the generated subscriptions: there is
// no consumer for free-form extra configs, and a half-parsed merge only produced
// entries that never reached a client. An explicit whitelist keeps this from
// becoming an arbitrary write primitive -- the names below are exactly what
// lives in <data>.
namespace {

struct RawFileSpec {
    const char* name;
    bool restart_required;
};

// settings.json is deliberately absent: it is the panel's own state and is
// rewritten on every save, so writing it here would silently lose the values
// the form just posted. These four are the files a user may legitimately want
// to replace by hand.
const RawFileSpec kRawFiles[] = {
    {"config.json", true},
    {"passwd", true},
    {"tunnel-quick.json", true},
};

const RawFileSpec* raw_file_spec(const std::string& name) {
    for (const auto& s : kRawFiles) {
        if (name == s.name) return &s;
    }
    return nullptr;
}

} // namespace

http::Response App::list_raw_files() {
    nlohmann::json files = nlohmann::json::array();
    const std::string dir = store_.dir();
    for (const auto& spec : kRawFiles) {
        nlohmann::json entry = {{"name", spec.name}, {"present", false}, {"size", 0}};
        std::error_code ec;
        const std::string path = dir + "/" + spec.name;
        if (std::filesystem::exists(path, ec) && !ec) {
            entry["present"] = true;
            entry["size"] = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
        }
        files.push_back(entry);
    }
    nlohmann::json body;
    body["files"] = files;
    body["dir"] = dir;
    return json_ok(body);
}

http::Response App::import_raw_files(const http::Request& req) {
    if (req.method != "PUT") return json_err(405, "请求方法不允许。");
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(req.body);
    } catch (...) {
        return json_err(400, "请求体不是合法 JSON。");
    }
    if (!data.contains("files") || !data["files"].is_object())
        return json_err(400, "缺少 files 字段。");

    nlohmann::json written = nlohmann::json::array();
    for (auto it = data["files"].begin(); it != data["files"].end(); ++it) {
        const std::string name = it.key();
        const RawFileSpec* spec = raw_file_spec(name);
        if (!spec) return json_err(400, "不允许写入的文件：" + name);
        if (!it.value().is_string()) return json_err(400, name + " 的内容必须是字符串。");
        const std::string content = it.value().get<std::string>();
        // A JSON file that does not parse is almost certainly a mistake, and
        // writing it would leave the process unable to start. Validate before
        // touching the real file.
        if (name.size() > 5 && name.compare(name.size() - 5, 5, ".json") == 0) {
            const nlohmann::json probe = nlohmann::json::parse(content, nullptr, false);
            if (probe.is_discarded()) return json_err(400, name + " 不是合法 JSON，已放弃写入。");
        }
        if (!write_file(store_.dir() + "/" + name, content))
            return json_err(500, "写入 " + name + " 失败。");
        written.push_back(name);
    }
    nlohmann::json body;
    body["written"] = written;
    body["note"] = "文件已覆盖，重启进程后生效。";
    return json_ok(body);
}
namespace {

// Public address a client used to reach this panel, taken from the request that
// asked for the subscription. Only the address literal is trusted -- the port
// comes from the Host header too, because the process may be listening on 8080
// behind a mapping to 45566 (the experiment VPS is exactly that: 45566 -> 8080),
// and publishing the bind port produces links nobody can reach.
//
// A hand-configured directHost wins: it is an explicit statement of what the
// public address is, and a reverse proxy that rewrites Host would otherwise
// silently overwrite it. Only an empty/unset value is filled in here.
void adopt_request_host(bpb::Store& store, const bpb::http::Request& req) {
    std::string host = req.header("host");
    if (host.empty()) return;
    // Host may be "name", "name:port" or "[v6]:port".
    std::string name = host;
    int port = 0;
    // "name:port", "name", "[v6]:port". A bare IPv6 literal has several colons
    // and no brackets, so only split when the part after the last colon is
    // entirely numeric -- that is the only unambiguous case.
    const auto colon = host.rfind(':');
    if (colon != std::string::npos) {
        const std::string tail = host.substr(colon + 1);
        if (!tail.empty() && tail.size() <= 5 &&
            tail.find_first_not_of("0123456789") == std::string::npos) {
            name = host.substr(0, colon);
            port = std::atoi(tail.c_str());
            if (port <= 0 || port > 65535) port = 0;
        }
    }
    if (!name.empty() && name.front() == '[' && name.back() == ']')
        name = name.substr(1, name.size() - 2);
    name = trim(name);
    if (name.empty()) return;
    // Loopback is what a local check uses; publishing it would be useless but
    // harmless, and the operator may genuinely be on the box. Keep it simple:
    // only skip when we already have a usable public address.
    if (!store.config().directHost.empty() && store.config().directHost != "localhost" &&
        store.config().directHost != name) {
        return;
    }
    bool dirty = false;
    if (store.config().directHost != name) {
        store.config().directHost = name;
        dirty = true;
    }
    // The port from the Host header is the *public* one (45566 on the test box,
    // mapping to 8080 inside). It is exactly what a client must dial, so it is
    // what directPort means here -- the bind port is a separate fact the
    // generator falls back to when this is unset.
    if (port > 0 && store.config().directPort != port) {
        store.config().directPort = port;
        dirty = true;
    }
    // While the tunnel is off this is also the published domain, so a
    // subscription fetched from the public address immediately describes that
    // same address instead of "localhost".
    const bool tunnel_on = store.kv().contains("cfTunnel") && store.kv()["cfTunnel"].is_object() &&
                           store.kv()["cfTunnel"].value("enabled", false);
    if (!tunnel_on) {
        const std::string adopted = store.kv().value("tunnelAdoptedDomain", std::string());
        const std::string cur = store.config().mainDomain;
        if (cur.empty() || cur == "localhost" || cur == adopted || cur != name) {
            if (cur != name) {
                store.config().mainDomain = name;
                dirty = true;
            }
        }
    }
    if (dirty) {
        std::string err;
        if (!store.save(err))
            bpb::log::error("[panel] could not persist public address: %s", err.c_str());
    }
}

} // namespace

http::Response App::update_settings(const http::Request& req) {
    if (req.method != "PUT") return json_err(405, "请求方法不允许。");
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(req.body);
    } catch (...) {
        return json_err(400, "请求体不是合法 JSON。");
    }
    if (!data.is_object()) return json_err(400, "设置必须是 JSON 对象。");

    // 协议裁剪：只接受这个二进制真正编进来的入栈协议。别的构建（或上游）的
    // settings.json 可能带着没编进来的协议，存下去只会生成连不上的订阅链接。
    if (data.contains("protocols")) {
        std::string wanted;
        if (data["protocols"].is_string()) {
            wanted = data["protocols"].get<std::string>();
        } else if (data["protocols"].is_array()) {
            for (const auto& v : data["protocols"]) {
                if (!v.is_string()) continue;
                if (!wanted.empty()) wanted += ',';
                wanted += v.get<std::string>();
            }
        }
        std::string kept;
        for (const std::string& proto : split(wanted, ',')) {
            if (!inbound::has(proto)) continue;
            if (!kept.empty()) kept += ',';
            kept += proto;
        }
        if (kept.empty()) {
            return json_err(400, "这个二进制没有编入所选的入栈协议，可用： " + inbound::id_list());
        }
        data["protocols"] = kept;
    }

    auto& kv = store_.kv();
    for (auto it = data.begin(); it != data.end(); ++it) {
        if (!kv.contains(it.key())) continue;
        // Booleans that the panel renders as a <select> arrive as the strings
        // "true"/"false" (only checkboxes submit real booleans). Storing the
        // string in place of the boolean makes every later
        // value("...", true) throw a json type_error -- which surfaced as
        // "Internal Server Error" on /panel/warp-status right after turning the
        // WARP dry run off. Coerce back to the type the key already has.
        if (kv[it.key()].is_boolean() && it.value().is_string() &&
            (it.value().get<std::string>() == "true" || it.value().get<std::string>() == "false")) {
            kv[it.key()] = (it.value().get<std::string>() == "true");
            continue;
        }
        kv[it.key()] = it.value();
    }

    // The panel submits the WireGuard outbound as two flat fields; fold them
    // into the nested wgOutbound object.
    if (!kv.contains("wgOutbound") || !kv["wgOutbound"].is_object()) {
        kv["wgOutbound"] = nlohmann::json::object();
    }
    auto& wg = kv["wgOutbound"];
    if (data.contains("wgOutboundEnabled")) {
        std::string v = data["wgOutboundEnabled"].is_string()
                            ? data["wgOutboundEnabled"].get<std::string>()
                            : (data["wgOutboundEnabled"].is_boolean() &&
                                       data["wgOutboundEnabled"].get<bool>()
                                   ? "true"
                                   : "false");
        wg["enabled"] = (v == "true");
    }
    if (data.contains("wgOutboundEndpoint") && data["wgOutboundEndpoint"].is_string()) {
        std::string v = data["wgOutboundEndpoint"].get<std::string>();
        if (!v.empty()) wg["endpoint"] = v;
    }
    // Refuse to switch the outbound on with an empty account pool. It used to be
    // pre-filled with two hard-coded registrations that no longer worked, so
    // "enabled" looked applied while every connection quietly fell back to a
    // direct socket. Storing enabled=false and reporting why is the honest
    // outcome; the panel turns this into "请先注册账号".
    bool wg_needs_account = false;
    if (wg.value("enabled", false) &&
        (!store_.warps().is_array() || store_.warps().empty())) {
        wg["enabled"] = false;
        wg_needs_account = true;
    }

    // Cloudflare Tunnel: flat panel fields folded into the nested cfTunnel object.
    if (!kv.contains("cfTunnel") || !kv["cfTunnel"].is_object()) {
        kv["cfTunnel"] = nlohmann::json::object();
    }
    auto& ct = kv["cfTunnel"];
    // The connector's origin is not a user setting: it is this process's own
    // listener, so derive it instead of accepting a typed value. The two fields
    // used to be free text, which is how a panel showing "监听端口 8080" while
    // the process listened on 45566 could rewrite the tunnel's back end to a
    // port nothing was bound to (Cloudflare then answers 502/530).
    if (data.contains("cfTunnelEnabled")) {
        std::string v = data["cfTunnelEnabled"].is_string()
                            ? data["cfTunnelEnabled"].get<std::string>()
                            : (data["cfTunnelEnabled"].is_boolean() &&
                                       data["cfTunnelEnabled"].get<bool>()
                                   ? "true"
                                   : "false");
        ct["enabled"] = (v == "true");
    }
    // The tunnel and the two extra transports are mutually exclusive, and this is
    // the authoritative place to enforce it: the edge rewrites every request into
    // a plain HTTP/1.1 round trip, so a gRPC h2c preface never arrives and an XHTTP
    // downlink is reset (RST_STREAM CANCEL) before its first byte. Only the
    // WebSocket upgrade is passed through. The panel disables the pair when the
    // tunnel is on, but a stale tab or a direct API call could still post them
    // together, so the tunnel wins here and the switches are stored off.
    if (ct["enabled"].is_boolean() && ct["enabled"].get<bool>()) {
        kv["enableXHTTP"] = false;
        kv["enableGRPC"] = false;
    }
    if (data.contains("cfTunnelToken") && data["cfTunnelToken"].is_string()) {
        std::string v = data["cfTunnelToken"].get<std::string>();
        if (!v.empty()) ct["token"] = v;
    }
    ct["originHost"] = "127.0.0.1";
    ct["originPort"] = store_.listen_port();

    // Apply the WireGuard switch immediately. Without this the panel only wrote
    // the flag: saving "enabled" left ready=false until the process was
    // restarted, so the UI reported 已启用/未就绪 with no way to tell why.
    const bool wgTouched = data.contains("wgOutboundEnabled") ||
                           data.contains("wgOutboundEndpoint");

    auto& cfg = store_.config();
    if (data.contains("vlUUID")) cfg.vlUUID = data["vlUUID"].get<std::string>();
    if (data.contains("securePath")) cfg.securePath = data["securePath"].get<std::string>();
    if (data.contains("proxyIpMode")) cfg.proxyIpMode = data["proxyIpMode"].get<std::string>();
    if (data.contains("proxyIPs")) cfg.proxyIPs = data["proxyIPs"].get<std::vector<std::string>>();
    if (data.contains("prefixes")) cfg.prefixes = data["prefixes"].get<std::vector<std::string>>();
    if (data.contains("fallback")) cfg.fallback = data["fallback"].get<std::string>();
    if (data.contains("dohUrl")) cfg.dohUrl = data["dohUrl"].get<std::string>();
    // Address a client dials when the tunnel is off. Kept out of kv() on
    // purpose: it lives in config.json next to mainDomain, and the panel's flat
    // field loop only copies keys that already exist in kv().
    if (data.contains("directHost") && data["directHost"].is_string()) {
        const std::string v = trim(data["directHost"].get<std::string>());
        cfg.directHost = v;
        // This is also the value the tunnel rollback restores, so keep the
        // published domain in step whenever the tunnel is not the entrance.
        const bool tunnel_on = store_.kv().contains("cfTunnel") &&
                               store_.kv()["cfTunnel"].is_object() &&
                               store_.kv()["cfTunnel"].value("enabled", false);
        if (!tunnel_on && !v.empty()) store_.config().mainDomain = v;
    }
    if (data.contains("directPort")) {
        int v = 0;
        if (data["directPort"].is_number_integer()) v = data["directPort"].get<int>();
        else if (data["directPort"].is_string()) v = std::atoi(data["directPort"].get<std::string>().c_str());
        if (v > 0 && v <= 65535) cfg.directPort = v;
    }

    std::string error;
    if (!store_.save(error)) return json_err(500, error);

    // The tunnel switch is applied live, exactly like the WireGuard one below:
    // writing cfTunnel.enabled without telling the connector left a "disabled"
    // tunnel connected to the edge until the next restart.
    if (data.contains("cfTunnelEnabled")) tunnel::apply_store_state(store_);

    nlohmann::json out = nlohmann::json::object();
    if (wgTouched) {
        // start_wg_outbound blocks up to 6s waiting for the handshake, so the
        // switch is applied only after the settings are safely on disk: a
        // timeout then still leaves a consistent config behind.
        std::string wgError;
        const bool ready = net::apply_wg_outbound(store_, wgError);
        out["wgOutbound"] = {{"ready", ready},
                             {"status", net::wg_outbound_status()},
                             {"error", ready ? std::string() : wgError},
                             {"needsAccount", wg_needs_account}};
        if (wg_needs_account) {
            return json_err(400,
                            "WireGuard 出栈需要先注册 WARP 账号：面板里点“续期”或"
                            "“注册”获取，注册成功后再打开这个开关。开关已保持关闭。");
        }
    }
    return json_ok(out);
}

http::Response App::reset_settings() {
    store_.kv() = Store::default_kv();
    std::string error;
    if (!store_.save(error)) return json_err(500, error);
    return json_ok(store_.merged());
}

http::Response App::reset_password(const http::Request& req) {
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
    } catch (...) {
        return json_err(400, "请求体不是合法 JSON。");
    }
    if (store_.has_pwd() && !authenticated(req)) return json_err(401, "Unauthorized.");
    std::string username = to_lower(data.value("username", ""));
    if (!store_.has_pwd() && username != to_lower(store_.config().accEmail)) {
        return json_err(400, "用户名错误。");
    }
    // Write the credential straight to <data>/passwd and keep only a marker in
    // settings.json: the plaintext password must never be persisted there, and
    // the hashed file is what every later check reads.
    const std::string password = data.value("password", "");
    const std::string user = username.empty() ? store_.config().accEmail : username;
    std::string error;
    if (!password.empty()) {
        if (!app::passwd::save(store_.dir(), user, password, error))
            return json_err(500, "保存密码失败：" + error);
        store_.pwd() = "\x01";   // marker only
        // A new credential invalidates every existing session.
        (void)store_.rotate_secret();
    }
    if (!store_.save(error)) return json_err(500, error);
    return json_ok(nullptr);
}

http::Response App::my_ip(const http::Request& req) {
    std::string ip = trim(req.body);
    if (ip.empty()) return json_err(400, "缺少 IP 地址。");
    std::string url = "http://ip-api.com/json/" + url_encode(ip) + "?nocache=" + std::to_string(std::time(nullptr));
    net::httpc::Response upstream;
    std::string error;
    if (!net::httpc::get(url, upstream, error, 8000)) {
        return json_err(500, "获取 IP 信息失败： " + error);
    }
    try {
        return json_ok(nlohmann::json::parse(upstream.body));
    } catch (...) {
        return json_err(502, "ip-api.com 返回内容无法解析");
    }
}

http::Response App::doh(const http::Request& req) {
    std::string base = store_.config().dohUrl;
    if (base.empty()) base = "https://cloudflare-dns.com/dns-query";
    std::string target = base;
    if (!req.query.empty()) target += (base.find('?') == std::string::npos ? "?" : "&") + req.query;

    net::httpc::Headers headers;
    std::string accept = req.header("accept");
    headers.push_back({"Accept", accept.empty() ? "application/dns-message" : accept});
    std::string content_type = req.header("content-type");
    if (!content_type.empty()) headers.push_back({"Content-Type", content_type});

    net::httpc::Response upstream;
    std::string error;
    bool ok = false;
    if (req.method == "POST") {
        ok = net::httpc::post(target, req.body, upstream, error, 10000, headers);
    } else {
        ok = net::httpc::get(target, upstream, error, 10000, headers);
    }
    if (!ok) return http::Response::text(502, "DoH 上游请求失败： " + error);

    http::Response res;
    res.status = upstream.status;
    std::string ct = upstream.header("content-type");
    res.set("Content-Type", ct.empty() ? "application/dns-message" : ct);
    res.set("Cache-Control", "no-store");
    res.body = upstream.body;
    return res;
}

http::Response App::qrcode(const http::Request& req) {
    auto params = req.params();
    std::string data = params.count("data") ? params["data"] : std::string();
    if (data.empty()) return http::Response::text(400, "缺少 data 参数");

    // only render QR codes that point back at this panel (same as the TS implementation)
    std::string host = req.header("host");
    net::httpc::Url parsed;
    std::string error;
    if (net::httpc::parse_url(data, parsed, error)) {
        if (!host.empty() && parsed.host != host &&
            host.find(parsed.host) == std::string::npos) {
            return render_error(404, "页面不存在");
        }
    }

    std::string png;
    if (!generate_qr_png(data, png, error)) {
        return http::Response::text(500, "二维码生成失败： " + error);
    }
    http::Response res;
    res.status = 200;
    res.set("Content-Type", "image/png");
    res.set("Cache-Control", "no-store");
    res.body = std::move(png);
    return res;
}

http::Response App::render_error(int status, const std::string& message) {
    std::string page_error;
    std::string html = render_page("error", false, page_error);
    if (html.empty()) return http::Response::text(status, message);
    html = replace_all(std::move(html), "__ERROR_MESSAGE__", message);
    auto res = http::Response::html(html);
    res.status = status;
    return res;
}

http::Response App::handle(const http::Request& req) {
    std::string path = req.path;
    std::string sp = "/" + store_.config().securePath;

    // The panel is served under <securePath>/panel; send people there instead of answering 404.
    if (path == "/" || path.empty()) return http::Response::redirect(sp + "/panel");
    if (path == sp || path == sp + "/") return http::Response::redirect(sp + "/panel");

    if (path == sp + "/login") {
        if (authenticated(req)) return http::Response::redirect("./panel");
        std::string page_error;
        return http::Response::html(render_page("login", false, page_error));
    }
    if (path == sp + "/login/authenticate") return login(req);

    // Every panel request is gated, including one that arrives on the loopback
    // interface: a browser on the box, an SSH port-forward to the panel, and this
    // process's own tunnel all reach 127.0.0.1 and used to be let in without a
    // password. The command line still has full access -- see authenticated(),
    // where it identifies itself with X-BPB-CLI instead of an address.
    const bool needs_auth = store_.has_pwd();
    if (path == sp + "/panel") {
        if (needs_auth && !authenticated(req)) return http::Response::redirect("./login");
        std::string page_error;
        return http::Response::html(render_page("panel", true, page_error));
    }
    if (path == sp + "/panel/settings") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        return panel_settings();
    }
    if (path == sp + "/panel/update-settings") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        return update_settings(req);
    }
    if (path == sp + "/panel/raw-files") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        if (req.method == "PUT") return import_raw_files(req);
        return list_raw_files();
    }
    if (path == sp + "/panel/reset-settings") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        return reset_settings();
    }
    if (path == sp + "/panel/reset-password") return reset_password(req);
    // Re-read the files on disk and hand back the same shape /panel/settings
    // returns. The status readouts used to be built from the in-memory snapshot
    // taken at startup, so an account pool or a settings.json changed by hand
    // (or by the CLI) disagreed with the file until the process restarted.
    if (path == sp + "/panel/reload") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        if (req.method != "POST") return json_err(405, "请求方法不允许。");
        std::string reload_error;
        if (!store_.reload_from_disk(reload_error))
            return json_err(500, "重新读取数据目录失败：" + reload_error);
        return panel_settings();
    }
    if (path == sp + "/panel/logout") return logout();
    if (path == sp + "/panel/usage") return not_supported("用量统计（仅 Cloudflare 版）");
    if (path == sp + "/panel/my-ip") return my_ip(req);
    if (path == sp + "/panel/update-warp") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        if (req.method != "POST") return json_err(405, "请求方法不允许。");
        nlohmann::json accounts;
        std::string error;
        if (!sub::fetch_warp_accounts(accounts, error))
            return json_err(500, "Failed to update WARP configs: " + error);
        store_.warps() = accounts;
        if (!store_.save(error)) return json_err(500, error);
        // Re-read the file so the reply describes the disk, not the vector this
        // request happens to hold.
        std::string reload_error;
        if (!store_.reload_from_disk(reload_error))
            bpb::log::error("[warp] saved the accounts but could not re-read them: %s",
                            reload_error.c_str());
        return json_ok(accounts);
    }
    // ---- WARP outbound ------------------------------------------------------
    // The WARP outbound is in-process (in-tree WireGuard + lwIP), so the panel
    // surface is just status plus an explicit registration action. Registration
    // defaults to a dry run so the round trip is testable without consuming
    // Cloudflare's per-IP quota.
    if (path == sp + "/panel/warp-status") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        nlohmann::json out;
        out["enabled"] = false;
        if (store_.kv().contains("wgOutbound") && store_.kv()["wgOutbound"].is_object())
            out["enabled"] = store_.kv()["wgOutbound"].value("enabled", false);
        out["ready"] = net::wg_outbound_ready();
        out["status"] = net::wg_outbound_status();
        out["dryRun"] = store_.kv().value("warpRegisterDryRun", true);
        // Counted from settings.json, not from the in-memory pool: this endpoint
        // answers "how many accounts does the box have", and the file is the only
        // thing that survives a restart or a CLI edit. memoryOnly is reported too
        // so a mismatch is visible instead of silently papered over.
        out["accounts"] = store_.warp_accounts_on_disk();
        out["memoryOnly"] = store_.warps().size();
        return json_ok(out);
    }
    if (path == sp + "/panel/warp-register") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        if (req.method != "POST") return json_err(405, "请求方法不允许。");
        const bool dry_run = store_.kv().value("warpRegisterDryRun", true);
        nlohmann::json accounts;
        std::string error;
        if (!sub::fetch_warp_accounts(accounts, error, dry_run))
            return json_err(500, "注册 WARP 账号失败：" + error);
        // A dry run must not touch the live account pool: its synthetic account
        // has no working keys, so persisting it would silently break the outbound
        // (the next start would hand the stack an unusable account).
        if (!dry_run) {
            store_.warps() = accounts;
            if (!store_.save(error)) return json_err(500, "保存设置失败：" + error);
            // Read back what actually landed on disk instead of echoing the
            // in-memory vector: the panel (and the operator) then sees the file
            // the process is really going to use on its next start.
            std::string reload_error;
            if (store_.reload_from_disk(reload_error)) {
                bpb::log::info("[warp] reloaded %zu account(s) from disk",
                               store_.warps().size());
            } else {
                bpb::log::error("[warp] saved the accounts but could not re-read them: %s",
                                reload_error.c_str());
            }
        }
        nlohmann::json out;
        out["dryRun"] = dry_run;
        out["accounts"] = dry_run ? accounts : store_.warps();
        out["count"] = store_.warp_accounts_on_disk();
        out["saved"] = !dry_run;
        out["note"] = dry_run ? "dry run：未访问 Cloudflare，未写入账号池"
                              : "已真实注册并写入账号池";
        return json_ok(out);
    }
    // ---- trimmed Cloudflare Tunnel, woken on demand -------------------------
    if (path == sp + "/panel/tunnel-status") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        // The edge's ingress configuration is the authority on the public
        // hostname, so pick it up here (HTTP thread owns the store) and hand
        // the resulting domain to the panel alongside the live state.
        tunnel::sync_ingress_domain(store_);
        nlohmann::json st = nlohmann::json::parse(tunnel::status_json(), nullptr, false);
        if (st.is_discarded()) st = nlohmann::json::object();
        st["mainDomain"] = store_.config().mainDomain;
        return http::Response::json(200, st.dump());
    }
    if (path == sp + "/panel/tunnel-wake") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        if (req.method != "POST") return json_err(405, "请求方法不允许。");
        auto& kv = store_.kv();
        if (!kv.contains("cfTunnel") || !kv["cfTunnel"].is_object())
            kv["cfTunnel"] = nlohmann::json::object();
        kv["cfTunnel"]["enabled"] = true;
        std::string error;
        if (!store_.save(error)) return json_err(500, "保存设置失败：" + error);
        bool started = false;
        if (!tunnel::start_from_store(store_, started, error)) return json_err(500, error);
        nlohmann::json st = nlohmann::json::parse(tunnel::status_json(), nullptr, false);
        if (st.is_discarded()) st = nlohmann::json::object();
        st["mainDomain"] = store_.config().mainDomain;
        return json_ok(st);
    }
    if (path == sp + "/panel/tunnel-sleep") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        if (req.method != "POST") return json_err(405, "请求方法不允许。");
        auto& kv = store_.kv();
        if (!kv.contains("cfTunnel") || !kv["cfTunnel"].is_object())
            kv["cfTunnel"] = nlohmann::json::object();
        kv["cfTunnel"]["enabled"] = false;
        std::string error;
        if (!store_.save(error)) return json_err(500, "保存设置失败：" + error);
        tunnel::stop();
        // The tunnel is down now, so the domain it lent us has to go with it:
        // leaving it in place is what made "sleep" produce configs pointing at
        // a hostname the edge no longer routes (530).
        tunnel::release_adopted_domain(store_);
        // Report the live state, not a hard-coded flag: the ingress hostnames
        // survive a sleep and the panel shows them under "隧道域名".
        nlohmann::json st = nlohmann::json::parse(tunnel::status_json(), nullptr, false);
        if (st.is_discarded()) st = nlohmann::json::object();
        st["mainDomain"] = store_.config().mainDomain;
        return json_ok(st);
    }
    // ---- TLS certificate: view and regenerate -------------------------------
    if (path == sp + "/panel/tls-cert") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        nlohmann::json out = nlohmann::json::object();
        const int tls_port = store_.tls_port();
        out["tlsPort"] = tls_port;
        out["enabled"] = tls_port > 0;
        const std::string cert_path = store_.tls_cert_path();
        out["path"] = cert_path;
        if (!cert_path.empty()) {
            const net::CertInfo info = net::inspect_cert(cert_path);
            out["ok"] = info.ok;
            out["subject"] = info.subject;
            out["notAfter"] = info.not_after;
            out["sha256"] = info.sha256;
            out["error"] = info.error;
        } else {
            out["ok"] = false;
            out["error"] = "没有启用 TLS 监听（以 --tls-port 启动才会有）";
        }
        return json_ok(out);
    }
    if (path == sp + "/panel/tls-cert-regenerate") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        if (req.method != "POST") return json_err(405, "请求方法不允许。");
        const std::string cert_path = store_.tls_cert_path();
        if (cert_path.empty()) return json_err(400, "没有启用 TLS 监听，无法生成证书。");
        // Keep the key next to the certificate; the naming is the same the
        // startup path uses.
        std::string key_path = cert_path;
        const auto slash = key_path.find_last_of('/');
        const auto dot = key_path.find_last_of('.');
        if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
            key_path = key_path.substr(0, dot) + "-key.pem";
        else
            key_path += "-key.pem";
        const std::string cn = !store_.config().directHost.empty() ? store_.config().directHost
                                                                  : store_.config().mainDomain;
        std::string error;
        if (!net::regenerate_self_signed(cert_path, key_path, cn, error))
            return json_err(500, "生成证书失败：" + error);
        const net::CertInfo info = net::inspect_cert(cert_path);
        store_.set_cert_pin(info.sha256);
        std::string saveError;
        if (!store_.save(saveError)) return json_err(500, "保存设置失败：" + saveError);
        // The listening context still holds the previous certificate; say so
        // instead of pretending the change is live.
        nlohmann::json out = nlohmann::json::object();
        out["ok"] = info.ok;
        out["subject"] = info.subject;
        out["notAfter"] = info.not_after;
        out["sha256"] = info.sha256;
        out["note"] = "证书已重新生成，重启进程后新证书才会用于 TLS 监听；订阅里的指纹已同步更新。";
        return json_ok(out);
    }
    if (path == sp + "/panel/update-panel") return not_supported("面板自更新（仅 Cloudflare 版）");
    if (path == sp + "/panel/delete-panel") return not_supported("面板删除（仅 Cloudflare 版）");
    if (starts_with(path, sp + "/sub/")) {
        // Subscriptions embed the domain clients dial. When the tunnel is up,
        // the edge's ingress configuration is the truth about which hostname
        // reaches this panel, so adopt it before building anything -- otherwise
        // a recreated tunnel keeps handing out the stale (dead) domain.
        tunnel::sync_ingress_domain(store_);
        // The panel has no way of knowing the address the outside world uses:
        // behind NAT / a port mapping / a reverse proxy the bind address and
        // port are both wrong, and "localhost" is what the operator then gets in
        // every line. The request itself carries the answer -- the browser asked
        // for http://<public-host>:<public-port>/<sp>/sub/... -- so when no
        // public address was configured by hand, adopt it for this request.
        adopt_request_host(store_, req);
        std::string kind = path.substr((sp + "/sub/").size());
        auto params = req.params();
        std::string client = params.count("app") ? params["app"] : std::string();

        if (kind == "share-settings") {
            nlohmann::json shared = store_.kv();
            shared.erase("remoteSettings");
            shared.erase("customDomain");
            shared.erase("panelVersion");
            shared["proxyIpMode"] = store_.config().proxyIpMode;
            shared["proxyIPs"] = store_.config().proxyIPs;
            shared["prefixes"] = store_.config().prefixes;
            shared["fallback"] = store_.config().fallback;
            shared["dohUrl"] = store_.config().dohUrl;
            http::Response res = http::Response::text(200, base64_encode(shared.dump()));
            res.set("Content-Disposition", "attachment; filename=bpb-settings.dat");
            res.set("Access-Control-Allow-Origin", "*");
            res.set("Access-Control-Allow-Methods", "GET");
            res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
            return res;
        }

        if ((client == "wireguard" && (kind == "warp" || kind == "warp-pro")) ||
            (client == "amnezia" && kind == "warp-pro")) {
            bool is_pro = (client == "amnezia" || kind == "warp-pro");
            std::string zip_out, error;
            if (!sub::build_wireguard_zip(store_.merged(), store_.warps(), is_pro, zip_out, error)) {
                return json_err(400, error);
            }
            http::Response res;
            res.status = 200;
            res.set("Content-Type", "application/zip");
            res.set("Content-Disposition",
                    "attachment; filename=bpb-warp-" +
                        std::string(client == "amnezia" ? "pro-amnezia" : "wireguard") + "-conf.zip");
            res.set("Cache-Control", "no-store, no-cache, must-revalidate");
            res.body = std::move(zip_out);
            return res;
        }

        if (kind == "raw") {
            auto result = sub::build_raw_configs(store_.merged(), client);
            if (result.status != 200) return json_err(result.status, result.body);
            http::Response res = http::Response::text(200, base64_encode(result.body));
            res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
            if (!result.profile_title.empty()) res.set("Profile-Title", result.profile_title);
            if (!result.dns.empty()) res.set("DNS", result.dns);
            return res;
        }
        if (client == "xray" || client == "xray-knocker") {
            std::string json_out, error;
            bool ok = false;
            std::string file_name = kind;
            if (kind == "normal") ok = sub::build_xray_custom(store_.merged(), false, json_out, error);
            else if (kind == "fragment") ok = sub::build_xray_custom(store_.merged(), true, json_out, error);
            else if (kind == "warp") ok = sub::build_xray_warp(store_.merged(), store_.warps(), false, false, json_out, error);
            else if (kind == "warp-pro") ok = sub::build_xray_warp(store_.merged(), store_.warps(), true, client == "xray-knocker", json_out, error);
            if (ok) {
                http::Response res = http::Response::json(200, json_out);
                res.set("Content-Disposition", "attachment; filename=bpb-" + file_name + "-xray.json");
                res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                return res;
            }
            return json_err(400, error.empty() ? ("Unsupported subscription: " + kind) : error);
        }
        if (client == "sing-box") {
            std::string json_out, error;
            bool ok = false;
            if (kind == "normal") ok = sub::build_sb_custom(store_.merged(), false, json_out, error);
            else if (kind == "fragment") ok = sub::build_sb_custom(store_.merged(), true, json_out, error);
            else if (kind == "warp") ok = sub::build_sb_warp(store_.merged(), store_.warps(), json_out, error);
            if (ok) {
                http::Response res = http::Response::json(200, json_out);
                res.set("Content-Disposition", "attachment; filename=bpb-" + kind + "-sing-box.json");
                res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                return res;
            }
            return json_err(400, error.empty() ? ("Unsupported subscription: " + kind) : error);
        }
        if (client == "clash") {
            std::string json_out, error;
            bool ok = false;
            if (kind == "normal") ok = sub::build_clash_custom(store_.merged(), json_out, error);
            else if (kind == "warp") ok = sub::build_clash_warp(store_.merged(), store_.warps(), false, json_out, error);
            else if (kind == "warp-pro") ok = sub::build_clash_warp(store_.merged(), store_.warps(), true, json_out, error);
            if (ok) {
                http::Response res = http::Response::json(200, json_out);
                res.set("Content-Disposition", "attachment; filename=bpb-" + kind + "-clash.json");
                res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                return res;
            }
            return json_err(400, error.empty() ? ("Unsupported subscription: " + kind) : error);
        }
        return not_supported("Subscription: " + kind + " for " + client);
    }
    if (path == sp + "/dns-query") return doh(req);
    if (path == sp + "/qrcode") return qrcode(req);

    return render_error(404, "页面不存在（请检查安全路径与地址）");
}

} // namespace bpb