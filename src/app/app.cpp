#include "app/app.h"
#include "app/qrcode.h"
#include "inbound/inbound.h"
#include "assets_gen.h"
#include "crypto/crypto.h"
#include "net/http_client.h"
#include "net/wg_outbound.h"
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

// Native build has no Cloudflare account/analytics/telegram integration: hide
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

bool App::authenticated(const http::Request& req) const {
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
    if (username != to_lower(store_.config().accEmail) || password != store_.pwd()) {
        return json_err(401, "用户名或密码错误。");
    }
    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    nlohmann::json payload;
    payload["id"] = store_.config().accID;
    payload["iat"] = now;
    payload["exp"] = now + 24 * 60 * 60;
    std::string token = crypto::jwt_sign_hs256(payload.dump(), store_.secret());
    http::Response res = json_ok(nullptr);
    res.set("Set-Cookie", "jwtToken=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400");
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
    body["telegramSettings"] = store_.telegram();
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
        if (kv.contains(it.key())) kv[it.key()] = it.value();
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

    // Cloudflare Tunnel: flat panel fields folded into the nested cfTunnel object.
    if (!kv.contains("cfTunnel") || !kv["cfTunnel"].is_object()) {
        kv["cfTunnel"] = nlohmann::json::object();
    }
    auto& ct = kv["cfTunnel"];
    if (data.contains("cfTunnelEnabled")) {
        std::string v = data["cfTunnelEnabled"].is_string()
                            ? data["cfTunnelEnabled"].get<std::string>()
                            : (data["cfTunnelEnabled"].is_boolean() &&
                                       data["cfTunnelEnabled"].get<bool>()
                                   ? "true"
                                   : "false");
        ct["enabled"] = (v == "true");
    }
    if (data.contains("cfTunnelToken") && data["cfTunnelToken"].is_string()) {
        std::string v = data["cfTunnelToken"].get<std::string>();
        if (!v.empty()) ct["token"] = v;
    }
    if (data.contains("cfTunnelOrigin") && data["cfTunnelOrigin"].is_string()) {
        std::string v = data["cfTunnelOrigin"].get<std::string>();
        if (!v.empty()) {
            auto colon = v.find(':');
            if (colon == std::string::npos) {
                ct["originHost"] = v;
            } else {
                ct["originHost"] = v.substr(0, colon);
                try {
                    ct["originPort"] = std::stoi(v.substr(colon + 1));
                } catch (...) {
                    // keep the previous port when the value is not numeric
                }
            }
        }
    }

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

    std::string error;
    if (!store_.save(error)) return json_err(500, error);

    nlohmann::json out = nlohmann::json::object();
    if (wgTouched) {
        // start_wg_outbound blocks up to 6s waiting for the handshake, so the
        // switch is applied only after the settings are safely on disk: a
        // timeout then still leaves a consistent config behind.
        std::string wgError;
        const bool ready = net::apply_wg_outbound(store_, wgError);
        out["wgOutbound"] = {{"ready", ready},
                             {"status", net::wg_outbound_status()},
                             {"error", ready ? std::string() : wgError}};
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
    store_.pwd() = data.value("password", "");
    std::string error;
    if (!store_.save(error)) return json_err(500, error);
    return json_ok(nullptr);
}

std::string App::telegram_api(const std::string& token, const std::string& method,
                              const std::string& body, std::string& error) {
    std::string url = "https://api.telegram.org/bot" + token + "/" + method;
    net::httpc::Response res;
    if (body.empty()) {
        if (!net::httpc::get(url, res, error, 10000, {})) return "";
    } else {
        if (!net::httpc::post(url, body, res, error, 10000,
                              {{"Content-Type", "application/json"}}))
            return "";
    }
    return res.body;
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

http::Response App::telegram_setup(const http::Request& req) {
    if (req.method != "PUT") return json_err(405, "请求方法不允许。");
    if (!authenticated(req)) return json_err(401, "未授权或会话已过期。");
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(req.body);
    } catch (...) {
        return json_err(400, "请求体不是合法 JSON。");
    }
    std::string token = trim(data.value("telegramBotToken", std::string()));
    std::string user_id = trim(data.value("telegramUserId", std::string()));
    if (token.empty() || user_id.empty()) return json_err(400, "缺少 Bot 信息。");

    std::string host = req.header("host");
    std::string base = store_.config().mainDomain.empty() || store_.config().mainDomain == "localhost"
                           ? host
                           : store_.config().mainDomain;
    if (base.empty()) base = "localhost";
    std::string webhook = "https://" + host + "/" + store_.config().securePath + "/telegram/webhook";

    std::string error;
    std::string body = telegram_api(token, "setWebhook?url=" + url_encode(webhook), "", error);
    if (body.empty()) return json_err(500, "Telegram setWebhook 失败： " + error);

    nlohmann::json commands = {
        {"commands", nlohmann::json::array({{{"command", "start"}, {"description", "ð¤ Show welcome menu"}},
                                            {{"command", "config"}, {"description", "ð Get configs"}},
                                            {{"command", "clients"}, {"description", "ð± Get supported clients"}},
                                            {{"command", "usage"}, {"description", "ð Monitor usage"}}})}};
    telegram_api(token, "setMyCommands", commands.dump(), error);

    store_.telegram()["telegramBotToken"] = token;
    store_.telegram()["telegramUserId"] = user_id;
    if (!store_.save(error)) return json_err(500, error);
    return json_ok(store_.telegram());
}

http::Response App::telegram_remove(const http::Request& req) {
    if (req.method != "POST") return json_err(405, "请求方法不允许。");
    if (!authenticated(req)) return json_err(401, "未授权或会话已过期。");
    std::string token = store_.telegram().value("telegramBotToken", std::string());
    std::string error;
    if (!token.empty()) {
        telegram_api(token, "deleteWebhook", R"({"drop_pending_updates":true})", error);
    }
    store_.telegram()["telegramBotToken"] = "";
    store_.telegram()["telegramUserId"] = "";
    if (!store_.save(error)) return json_err(500, error);
    return json_ok(store_.telegram());
}

http::Response App::telegram_webhook(const http::Request& req) {
    if (req.method != "POST") return json_err(405, "请求方法不允许。");
    nlohmann::json update;
    try {
        update = nlohmann::json::parse(req.body);
    } catch (...) {
        return json_err(400, "请求体不是合法 JSON。");
    }
    if (!update.contains("message") || !update["message"].is_object()) return json_ok(nullptr);
    auto& msg = update["message"];
    std::int64_t from_id = 0;
    if (msg.contains("from") && msg["from"].is_object()) from_id = msg["from"].value("id", (std::int64_t)0);
    std::int64_t chat_id = msg.contains("chat") && msg["chat"].is_object()
                               ? msg["chat"].value("id", (std::int64_t)0)
                               : 0;
    std::string text = msg.value("text", std::string());
    std::string expected = store_.telegram().value("telegramUserId", std::string());
    std::string token = store_.telegram().value("telegramBotToken", std::string());
    if (token.empty() || chat_id == 0) return json_ok(nullptr);
    if (!expected.empty() && std::to_string(from_id) != expected) return json_ok(nullptr);

    std::string reply;
    std::string host = req.header("host");
    std::string origin = "https://" + host + "/" + store_.config().securePath + "/sub";
    if (text == "/start") {
        reply = "\xF0\x9F\xA4\x96 BPB native bot\n/start - this menu\n/config - subscription links\n/clients - supported clients\n/usage - usage statistics";
    } else if (text == "/config") {
        std::vector<std::string> lines;
        for (auto& [kind, client] : std::vector<std::pair<std::string, std::string>>{
                 {"normal", "xray"}, {"normal", "sing-box"}, {"normal", "clash"}, {"raw", "xray"},
                 {"warp", "wireguard"}}) {
            lines.push_back(kind + " (" + client + "): " + origin + "/" + kind + "?app=" + client);
        }
        reply = join_lines(lines);
    } else if (text == "/clients") {
        reply = "v2rayNG, v2rayN, MahsaNG, Streisand, sing-box, husi, NekoBox, Hiddink, Clash Meta, "
                "Clash Verge, FlClash, Stash, Wireguard, Amnezia";
    } else if (text == "/usage") {
        reply = "Usage statistics are not available in the native build.";
    } else {
        reply = "Unknown command. Try /start";
    }

    nlohmann::json payload = {{"chat_id", chat_id}, {"text", reply}};
    std::string error;
    telegram_api(token, "sendMessage", payload.dump(), error);
    return json_ok(nullptr);
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

    bool needs_auth = store_.has_pwd();
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
    if (path == sp + "/panel/reset-settings") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        return reset_settings();
    }
    if (path == sp + "/panel/reset-password") return reset_password(req);
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
        return json_ok(accounts);
    }
    // ---- WARP outbound ------------------------------------------------------
    // Backend differs per branch (main: supervised warp-rust, warp-built-in:
    // in-tree WG + lwIP) but the panel surface is identical: status plus an
    // explicit registration action. Registration defaults to a dry run so the
    // round trip is testable without consuming Cloudflare's per-IP quota.
    if (path == sp + "/panel/warp-status") {
        if (needs_auth && !authenticated(req)) return json_err(401, "未授权或会话已过期。");
        nlohmann::json out;
        out["enabled"] = false;
        if (store_.kv().contains("wgOutbound") && store_.kv()["wgOutbound"].is_object())
            out["enabled"] = store_.kv()["wgOutbound"].value("enabled", false);
        out["ready"] = net::wg_outbound_ready();
        out["status"] = net::wg_outbound_status();
        out["dryRun"] = store_.kv().value("warpRegisterDryRun", true);
        out["accounts"] = store_.warps().size();
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
        }
        nlohmann::json out;
        out["dryRun"] = dry_run;
        out["accounts"] = accounts;
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
        // Report the live state, not a hard-coded flag: the ingress hostnames
        // survive a sleep and the panel shows them under "隧道域名".
        nlohmann::json st = nlohmann::json::parse(tunnel::status_json(), nullptr, false);
        if (st.is_discarded()) st = nlohmann::json::object();
        st["mainDomain"] = store_.config().mainDomain;
        return json_ok(st);
    }
    if (path == sp + "/panel/update-panel") return not_supported("面板自更新（仅 Cloudflare 版）");
    if (path == sp + "/panel/delete-panel") return not_supported("面板删除（仅 Cloudflare 版）");
    if (path == sp + "/telegram/setup") return telegram_setup(req);
    if (path == sp + "/telegram/remove") return telegram_remove(req);
    if (path == sp + "/telegram/webhook") return telegram_webhook(req);
    if (starts_with(path, sp + "/sub/")) {
        // Subscriptions embed the domain clients dial. When the tunnel is up,
        // the edge's ingress configuration is the truth about which hostname
        // reaches this panel, so adopt it before building anything -- otherwise
        // a recreated tunnel keeps handing out the stale (dead) domain.
        tunnel::sync_ingress_domain(store_);
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