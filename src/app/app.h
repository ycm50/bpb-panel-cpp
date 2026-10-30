#pragma once
#include "http/http.h"
#include "settings/store.h"

#include <string>

namespace bpb {

class App {
public:
    App(Store& store, std::string asset_dir);
    bool load_assets(std::string& error);
    http::Response handle(const http::Request& req);

    Store& store() { return store_; }

private:
    bool authenticated(const http::Request& req) const;
    std::string cookie(const http::Request& req, const std::string& name) const;

    http::Response panel_settings();
    http::Response update_settings(const http::Request& req);
    http::Response reset_settings();
    http::Response reset_password(const http::Request& req);
    http::Response login(const http::Request& req);
    http::Response logout();
    http::Response not_supported(const std::string& what);
    http::Response render_error(int status, const std::string& message);
    http::Response doh(const http::Request& req);
    http::Response qrcode(const http::Request& req);
    http::Response my_ip(const http::Request& req);
    http::Response telegram_setup(const http::Request& req);
    http::Response telegram_remove(const http::Request& req);
    http::Response telegram_webhook(const http::Request& req);
    std::string telegram_api(const std::string& token, const std::string& method,
                             const std::string& body, std::string& error);

    Store& store_;
    std::string asset_dir_;
    std::string panel_html_;
    std::string login_html_;
    std::string error_html_;
    std::string icon_b64_;
    std::string version_ = "1.0.0";
};

} // namespace bpb