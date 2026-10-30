#include "app/app.h"
#include "app/qrcode.h"
#include "assets_gen.h"
#include "crypto/crypto.h"
#include "net/http_client.h"
#include "sub/clash.h"
#include "sub/raw.h"
#include "sub/singbox.h"
#include "sub/warp.h"
#include "sub/wireguard.h"
#include "sub/xray.h"
#include "util/util.h"

#include <ctime>
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

bool App::load_assets(std::string& error) {
    // Assets are embedded in the binary; --assets can override them for UI tweaks without a rebuild.
    auto read_page = [&](const char* name, const std::string& path) -> std::string {
        std::string text = asset_dir_.empty() ? std::string() : read_text(path);
        if (!text.empty()) return text;
        std::size_t len = 0;
        const char* data = assets::page(name, len);
        return data ? std::string(data, len) : std::string();
    };

    std::string panel = read_page("panel", asset_dir_ + "/panel/index.html");
    std::string login = read_page("login", asset_dir_ + "/login/index.html");
    std::string err = read_page("error", asset_dir_ + "/error/index.html");

    std::string icon = read_text(asset_dir_ + "/favicon.ico");
    if (icon.empty()) {
        std::size_t len = 0;
        const char* data = assets::icon(len);
        if (data) icon.assign(data, len);
    }
    if (panel.empty() || login.empty()) {
        error = "no panel assets available (embedded assets missing and --assets dir has none)";
        return false;
    }

    icon_b64_ = base64_encode(icon);

    auto build = [&](std::string html) {
        html = replace_all(std::move(html), "__VERSION__", version_);
        html = replace_all(std::move(html), "__ICON__", icon_b64_);
        return html;
    };

    panel_html_ = build(panel);

    // Native build has no Cloudflare account/analytics/telegram integration: hide those controls
    // with CSS only, so the browser-side script keeps running against existing elements.
    static const char* kNativeHideCss =
        "<style>"
        ".section:has(#total-usage){display:none!important;}"
        ".dashboard-action:has(#updatePanel){display:none!important;}"
        ".dashboard-action:has(#deletePanel){display:none!important;}"

        "</style>";
    panel_html_ += kNativeHideCss;
    login_html_ = build(login);
    if (!err.empty()) error_html_ = build(err);
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

    auto& kv = store_.kv();
    for (auto it = data.begin(); it != data.end(); ++it) {
        if (kv.contains(it.key())) kv[it.key()] = it.value();
    }

    auto& cfg = store_.config();
    if (data.contains("vlUUID")) cfg.vlUUID = data["vlUUID"].get<std::string>();
    if (data.contains("trPass")) cfg.trPass = data["trPass"].get<std::string>();
    if (data.contains("securePath")) cfg.securePath = data["securePath"].get<std::string>();
    if (data.contains("proxyIpMode")) cfg.proxyIpMode = data["proxyIpMode"].get<std::string>();
    if (data.contains("proxyIPs")) cfg.proxyIPs = data["proxyIPs"].get<std::vector<std::string>>();
    if (data.contains("prefixes")) cfg.prefixes = data["prefixes"].get<std::vector<std::string>>();
    if (data.contains("fallback")) cfg.fallback = data["fallback"].get<std::string>();
    if (data.contains("dohUrl")) cfg.dohUrl = data["dohUrl"].get<std::string>();

    std::string error;
    if (!store_.save(error)) return json_err(500, error);
    return json_ok(nullptr);
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
    if (error_html_.empty()) return http::Response::text(status, message);
    std::string html = replace_all(error_html_, "__ERROR_MESSAGE__", message);
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
        return http::Response::html(login_html_);
    }
    if (path == sp + "/login/authenticate") return login(req);

    bool needs_auth = store_.has_pwd();
    if (path == sp + "/panel") {
        if (needs_auth && !authenticated(req)) return http::Response::redirect("./login");
        return http::Response::html(panel_html_);
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
    if (path == sp + "/panel/update-panel") return not_supported("面板自更新（仅 Cloudflare 版）");
    if (path == sp + "/panel/delete-panel") return not_supported("面板删除（仅 Cloudflare 版）");
    if (path == sp + "/telegram/setup") return telegram_setup(req);
    if (path == sp + "/telegram/remove") return telegram_remove(req);
    if (path == sp + "/telegram/webhook") return telegram_webhook(req);
    if (starts_with(path, sp + "/sub/")) {
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